#!/usr/bin/python

import sys
import json
import re
from deriva.core import ErmrestCatalog, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey, tag, AttrDict
from deriva.core import urlquote, urlunquote
import requests.exceptions

system_columns = ["RID", "RCT", "RMT", "RCB", "RMB"]

# -- =================================================================================
# -- data manipulation utilities
#
# ---------------------------------------------------------------
def approx_json_bytecnt(data):
    """Estimate byte count for JSON repr of input data as number of UTF-8 bytes.

    Does NOT try to estimate JSON indentation whitespace...
    """
    if isinstance(data, (list, tuple)):
        #  '[' ... ']'
        bytecnt = 2
        for elem in data:
            # elem + ','
            bytecnt += 1 + approx_json_bytecnt(elem)
        return bytecnt
    elif isinstance(data, dict):
        # '{' ... '}'
        bytecnt = 2
        for k, v in data.items():
            # key + ':' val + ','
            bytecnt = 2 + approx_json_bytecnt(k) + approx_json_bytecnt(v)
        return bytecnt
    elif isinstance(data, str):
        # '"' + UTF8 string + '"'
        # but also double count newline and backslash for escapes
        return 2 + len(data.encode('utf8')) + data.count('\n') + data.count('\\')
    elif isinstance(data, (int, float, bool)):
        # unquoted values do not add syntax
        return len(str(data))
    elif data is None:
        return 4
    else:
        raise TypeError('cannot estimate size of unexpected data %r' % data)

# ---------------------------------------------------------------
def get_batch_len(payload, index=0, batch_size=10000, batch_bytes=2000000, decrement=1000):
    """
    Calculate batch length based payload data. Try to fit the batch based on 2 heuristics:
    1) try batch_size and backoff based on decrement amount until fits
    2) Iterate over the payload and fill in one by one
    Note: Ensure a minimum batch size of one is returned
    """
    #print("payload: %s" % (payload))

    nrows = batch_size
    batch = payload[index:index+nrows]
    bytes = approx_json_bytecnt(batch)
    # -- try decrement batch_size by decrement amount first
    while bytes > batch_bytes:
        #print("!!! bytes: %d > batch_bytes: %d  nrows: %d --> Reduce batch size by %s" % (bytes, batch_bytes, nrows, decrement))        
        nrows = nrows - decrement
        if nrows < 0: nrows = 0
        batch = payload[index:index+nrows]
        bytes = approx_json_bytecnt(batch)

    # -- if the above doesn't work, iterate over each array element, add one by one.  
    if nrows <= 0:
        #print("+++ Iterate over payload")
        total_bytes = 0
        for i in range(len(payload)-index):
            total_bytes += approx_json_bytecnt(payload[index+i])
            #print("  index:%d,  i: %d, bytes: %d, total_bytes: %d" % (index, i, approx_json_bytecnt(payload[index+i]), total_bytes))
            if total_bytes > batch_bytes:
                break
        nrows = i  # nrows = the previous index before break + 1 (for size) e.g. i - 1 + 1

    # -- ensure a batch size of 1        
    if nrows <= 0: nrows = 1
    
    #print("-- index: %d, nrows: %d, bytecounts: %d, bytes: %s " % (index, nrows, approx_json_bytecnt(payload[index:index+nrows]), payload[index:index+nrows]))
    return nrows 

# ---------------------------------------------------------------
def insert_if_not_exist(catalog, schema_name, table_name, payload, defaults=None, batch_size=10000, batch_bytes=2000000):
    if not payload:
        return []

    if defaults:
        defaults_str = '&defaults=%s' % (','.join(list(map(urlquote, defaults))))
    else:
        defaults_str = ''

    inserted = []
    index = 0
    nrows = batch_size
    payload_len = len(payload)
    print("** insert_if_not_exist: %s:%s payload len: %d rows (%d bytes)" % (schema_name, table_name, payload_len, approx_json_bytecnt(payload)))
    
    while index < payload_len:
        batch = payload[index:index+nrows]
        bytes = approx_json_bytecnt(batch)
        while bytes > batch_bytes:
            nrows = nrows - 1000
            batch = payload[index:index+nrows]            
            bytes = approx_json_bytecnt(batch)
            
        if nrows <= 0: nrows = 1
        batch = payload[index:index+nrows]
        #print("index=%d nrows=%d bytes=%d" % (index, nrows, bytes))
        resp = catalog.post(
            "/entity/%s:%s?onconflict=skip%s" % (urlquote(schema_name), urlquote(table_name), defaults_str),
            json=batch
        )
        inserted.extend(resp.json())
        #print("inserting rows[%d:%d](%d bytes): %s:%s => \n%s " % (index, nrows, bytes, schema_name, table_name, json.dumps(resp.json(), indent=4, sort_keys=True)))        
        #print("  - inserting rows[%d:%d](%d bytes): %s:%s " % (index, index+nrows, bytes, schema_name, table_name))
        index = index + nrows
        nrows = batch_size

    return(inserted)

# ---------------------------------------------------------------
def update_table_rows(catalog, schema_name, table_name, keys=["RID"], column_names=[], payload=[], batch_size=10000, batch_bytes=2000000):
    model = catalog.getCatalogModel()
    if not payload:
        return []
    
    # if updaed_cname is NULL, use all columns except system columns
    if not column_names:
        column_names = []
        update_exclude_columns = keys + ["RID", "RCT", "RMT", "RCB", "RMB"]            
        for cname in  model.schemas[schema_name].tables[table_name].columns.elements:
            if cname not in update_exclude_columns:
                column_names.append(cname)
    cnames = ','.join([ urlquote(c) for c in column_names])
    if not cnames:
        print("ERROR: column names to be updated is empty")
        return []
    
    updated = []
    index = 0
    nrows = batch_size
    payload_len = len(payload)
    print("** update_table: %s:%s payload len: %d rows (%d bytes)" % (schema_name, table_name, payload_len, approx_json_bytecnt(payload)))
    
    while index < payload_len:
        batch = payload[index:index+nrows]
        bytes = approx_json_bytecnt(batch)
        while bytes > batch_bytes:  # TODO: better backoff algorithm
            nrows = nrows - 1000
            batch = payload[index:index+nrows]            
            bytes = approx_json_bytecnt(batch)
            
        if nrows <= 0: nrows = 1
        batch = payload[index:index+nrows]
        #print("- updating rows[%d:%d](%d bytes): %s:%s => \n%s " % (index, nrows, bytes, schema_name, table_name, json.dumps(batch, indent=4, sort_keys=True)))
        resp = catalog.put(
            "/attributegroup/%s:%s/%s;%s" % (urlquote(schema_name), urlquote(table_name), ','.join([ urlquote(k) for k in keys ]), cnames),
            json=batch
        )
        updated.extend(resp.json())
        print("  - updated rows[%d:%d](%d bytes): %s:%s " % (index, index+nrows, bytes, schema_name, table_name))
        index = index + nrows
        nrows = batch_size  # reset nrows        

    return(updated)

# ---------------------------------------------------------------
def get_key_for_dict(keys, row):
    if len(keys) == 1:
        return(row[keys[0]])
    index = []
    for key in keys:
        index.append(row[key])
    return(tuple(index))
    
# ---------------------------------------------------------------
def update_data_if_change(catalog, schema_name, table_name, keys, defaults='', constraints=None, update_columns=None, payload=[], batch_size=10000):
    pass

# ---------------------------------------------------------------
# TODO: make sure to return the right arrays!
# constraints is used to check the existing entries in the Ermrest
def insert_if_exist_update(catalog, schema_name, table_name, keys, defaults=None, payload=[], constraints=None, update_columns=None, batch_size=10000, limit=50000, bypass_insert=False):
    print("------ insert_if_not_exist ---------")
    #print(json.dumps(payload, indent=4))
    
    if not keys or not payload:
        print("Payload is empty")
        return None
    print("insert_if_exist_update: sname: %s, table: %s, keys: %s, defaults: %s, constraints: %s" % (schema_name, table_name, keys, defaults, constraints))
    inserted = []    
    # == try to insert first
    #   - excluding checking for "RID" in payload[0].keys()?
    if bypass_insert: # or "RID" in payload[0].keys():    
        print("  - BYPASS INSERT: bypass_insert (%s) is True or RID exist in payload: payload[0]=%s" % (bypass_insert, payload[0]))
    else:
        inserted = insert_if_not_exist(catalog, schema_name, table_name, payload, defaults, batch_size)
        print("  - INSERTED: %d rows inserted" % (len(inserted)))
        #print("  - INSERTED: %d rows inserted: %s" % (len(inserted), json.dumps(inserted, indent=4)))
        if len(payload) == len(inserted):
            print("  - COMPLETE: All rows are new: all inserted")
            return(payload)
            
    # == check for updates (rows that didn't get inserted)
    keys2rows = { get_key_for_dict(keys, row) : row for row in payload }
    keys2inserted = { get_key_for_dict(keys, row) : row for row in inserted }
    # -- check for rows that didn't get inserted
    keys2update = {}
    for (index, row) in keys2rows.items():
        if index in keys2inserted.keys(): continue
        keys2update[index] = row

    # == check update_columns: if not specified, include all columns except system columns
    attr_list = None    
    if not update_columns:
        attr_list = set(payload[0].keys()) - set(system_columns)
        update_columns = attr_list
            
    # == read existing rows from ermrest
    # -- if constraints is not provided, create constraints based on rows to be updated
    if not constraints:
        if len(keys) == 1:
            constraints = "%s=ANY(%s)" % (urlquote(keys[0]), ",".join([urlquote(row[keys[0]]) for row in keys2update.values()]))
        else:
            disjunctions = []
            for (index, row) in keys2update.items():
                conjunctions = []
                for key in keys:
                    conjunctions.append("%s=%s" % (urlquote(key), urlquote(row[key])))
                disjunctions.append("&".join(conjunctions))
            constraints = ";".join(disjunctions)
    print("  - getting existing rows with constraints = %s" % (constraints))
    # -- TODO: check for URL length limitation based on constraints. Retrieve only update_columns instead of all rows
    existing = get_ermrest_query(catalog, schema_name, table_name, constraints=constraints, keys=["RID"], attr_list=attr_list)
    #print("  - Getting existing rows with constraints %s from ermrest [%d]: %s" % (constraints, len(existing), json.dumps(existing, indent=4)))
    keys2existing = { get_key_for_dict(keys, row) : row for row in existing }
    
    # == update rows that are different only
    existed = []
    updated = []
    update_payload = []
    for index, new_row in keys2update.items():
        old_row = keys2existing[index]
        to_update = False
        for k in update_columns:
            if k in system_columns: continue
            if old_row[k] != new_row[k]:
                print("  - [%s]: key %s is different (%r:%s v.s. %r:%s)" % (old_row["RID"], k, old_row[k], type(old_row[k]), new_row[k], type(new_row[k])))
                to_update = True
                break
        if to_update:
            #print("  - update payload with RID:%s" % (old_row["RID"]))
            new_row["RID"] = old_row["RID"]
            update_payload.append(new_row)
        else:
            existed.append(old_row)
    if not update_payload:
        print("  - COMPLETE: Nothing new to update")
        return(inserted + existed)
    print("  - PARTIAL INSERT: will update %d rows" % (len(update_payload)))
    #print("  - PARTIAL INSERT: will update %d rows: %s" % (len(update_payload), json.dumps(update_payload, indent=4)))
    updated = update_table_rows(catalog, schema_name, table_name, key="RID", column_names=update_columns, payload=update_payload, batch_size=10000)
    return(inserted + existed + updated)
                           
# ---------------------------------------------------------------
# Example of response object: statis_code=204 headers={'Date': 'Fri, 27 Sep 2024 19:36:32 GMT', 'Server': 'Apache/2.4.59 (Fedora Linux) OpenSSL/3.0.9 mod_wsgi/4.9.4 Python/3.11', 'Set-Cookie': 'webauthn_track=ef32ad10.6231ef8ef6959; path=/; expires=Sat, 27-Sep-25 19:36:32 GMT', 'Vary': 'DNT,cookie,accept,User-Agent', 'Upgrade': 'h2', 'Connection': 'Upgrade, Keep-Alive', 'ETag': '"FvbI_TUNoSPPd3ANOP6-Ew==;*/*;2024-09-27 12:36:32.975696-07:00"', 'Keep-Alive': 'timeout=5, max=100'}

def delete_table_rows(catalog, schema_name, table_name, constraints=None, key="RID", values=None):
    #print("sname: %s, tname: %s, constraints: %s, key:%s, values:%s" % (schema_name, table_name, constraints, key, values))
    # no constraint will cause all rows to be deleted!!
    if not values and not constraints:
        raise Exception("DELETE ERROR: delete operation needs constraints")
    # prioritize key values.
    # TODO: address multi-keys?
    if key and values:
        constraints = "%s=ANY(%s)" % (urlquote(key), ",".join([ urlquote(v) for v in values ]))
    try:
        url = "/entity/M:=%s:%s/%s" % (urlquote(schema_name), urlquote(table_name), constraints)    
        resp = catalog.delete(url)
        #print("delete_table_rows: status_code: %s, headers: %s" % (resp.status_code, resp.headers))
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print("delete_table_rows: WARNING: ROWS NOT FOUND: url:%s status_code=%s NOT FOUND" % (url, e.response.status_code))
        else:
            #print("ERROR: url:%s, errors=%s" % (url, e))
            raise 

# ---------------------------------------------------------------

def delete_table_rows_by_keys(catalog):
    pass

# ---------------------------------------------------------------

# assignment has to happen with alias
def urlquote_list(attr_list):
    quoted_list = []
    for attr in attr_list:
        # aggregate function e.g. Agg:=array(M:structure_id)
        m = re.search("^([^:=]+:=)?(array|array_d|cnt|cnt_d)+\\(([^:=]+:)*([^:=()]+)\\)$", attr)
        if m:
            if not m[1]: raise Exception("ERROR: Aggregate function '%s' needs an assignment" % (m[2]))
            m1 = urlquote(m[1].rsplit(":=",1)[0])+":=" 
            m2 = m[2]
            m3 = urlquote(m[3].rsplit(":",1)[0])+":" if m[3] else ""
            m4 = urlquote(m[4])
            quoted_list.append("%s%s(%s%s)" % (m1, m2, m3, m4))
        else:
            # parsing pattern A:=M:cname            
            m = re.search("^([^:=]+:=)*([^:=]+:)*([^:=]+)$", attr)        
            if not m: raise Exception("ERROR: Can't parse attribute names")
            #print("attr: %s " % (attr))
            m1 = urlquote(m[1].rsplit(":=",1)[0])+":=" if m[1] else ""
            m2 = urlquote(m[2].rsplit(":",1)[0])+":" if m[2] else ""
            quoted_list.append("%s%s%s" % (m1, m2, m[3] if m[3]=='*' else urlquote(m[3])))
    #print("quoted_list: %s" % (quoted_list))
    return(quoted_list)

# ---------------------------------------------------------------
# example of descending order: "RID::desc::"
"""
  attr_list is a string attached to the query for projection/aggregate lists.
"""
def get_ermrest_query(catalog, schema_name, table_name, constraints=None, keys=["RID"], attributes=None, sort=["RID"], limit=None, batch_size=5000):
    payload = []
    if not limit:
        limit = 10000000
    after = []
    while True:
        page_size = limit if limit < batch_size else batch_size
        if attributes:
            url = "/attributegroup/M:=%s:%s" % (urlquote(schema_name), urlquote(table_name))
        else:
            url = "/entity/M:=%s:%s" % (urlquote(schema_name), urlquote(table_name))
        if constraints: url = "%s/%s" % (url, constraints)
        if attributes:
            quoted_keys = urlquote_list(keys)
            quoted_list = urlquote_list(attributes)
            url = "%s/%s;%s" % (url, ",".join(quoted_keys), ",".join(quoted_list))
        if sort:
            url = "%s@sort(%s)" % (url, ",".join(urlquote_list(sort)))
        if after: url = "%s@after(%s)" % (url, ",".join( [ urlquote(v) for v in after ]))
        url = "%s?limit=%d" % (url, page_size)
        print("get_ermrest_query: url = %s" % (url))
        rows = catalog.get(url).json()
        payload.extend(rows)
        n = len(rows)
        if len(rows) == 0 or n < batch_size:
            break
        else:
            after = [ rows[-1][k] for k in sort ]
            limit = limit - n
    return(payload)


# ---------------------------------------------------------------
def get_key2rows(catalog, schema_name, table_name, constraints='', keys=["RID"], attributes=None, sort=["RID"], limit=None):
    key2rows = {}
    rows = get_ermrest_query(catalog, schema_name, table_name, constraints=constraints, keys=keys, attributes=attributes, sort=sort, limit=limit)
    # strip alias from keys 
    dict_keys = [ k.rsplit(":", 1)[1] if len(k.rsplit(":", 1)) == 2 else k for k in keys ]
    if len(dict_keys) == 1:
        key2rows = { row[dict_keys[0]]: row for row in rows  }
    elif len(dict_keys) > 1:
        key2rows = { row[tuple(dict_keys)]: row for row in rows  }        
    return key2rows


# ===========================================================================

if __name__ == "__main__":
    cli = BaseCLI("extras", None, 1)
    cli.parser.add_argument('--catalog-id', metavar="<catalog_id>", help="catalog-id", default="99")
    args = cli.parse_cli()
    print(args)
    
    credentials = get_credential(args.host, args.credential_file)
    catalog = ErmrestCatalog("https", args.host, args.catalog_id, credentials)
    catalog.dcctx['cid'] = "cli/test"
    #store = HatracStore("https", args.host, credentials)

    payload=[ { "x": "0123456789-%d" % (i) } for i in range(100) ]
    batch_bytes=400
    index = 0
    while index < len(payload):
        nrows = get_batch_len(payload, index=index, batch_size=40, batch_bytes=batch_bytes, decrement=8)
        print("==> index: %d, nrows: %d, bytes: %d --> %s" % (index, nrows, approx_json_bytecnt(payload[index:index+nrows]), payload[index:index+nrows]))
        index = index + nrows

    
    #constraints = "T:=Vocab:System_Generated_File_Type/A:=Vocab:Archive_Category/$M"
    #attributes = ["RID2:=M:RID","File_Type:=M:File_Type","Archive_Category:=A:Name","Agg:=array(A:Directory_Name)"]
    #key2rows = get_key2rows(catalog, "PDB", "Entry_Generated_File", constraints=constraints, keys=["RID"], attributes=attributes, limit=10)
    #print(json.dumps(key2rows, indent=4))

    #2-RT98
    #delete_table_rows(catalog, "PDB", "entry", key="RID", values=['3-YT7G'])
