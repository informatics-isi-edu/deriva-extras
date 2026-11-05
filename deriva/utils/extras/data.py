#!/usr/bin/python

import sys
import json
import re
from deriva.core import ErmrestCatalog, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Model, Schema, Table, Column, Key, ForeignKey, tag, AttrDict, timestamptz_to_datetime
from deriva.core import urlquote, urlunquote
import requests.exceptions
import logging

logger = logging.getLogger(__name__)

system_columns = ["RID", "RCT", "RMT", "RCB", "RMB"]

URL_LENGTH_LIMIT = 2000  

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
            bytecnt += 2 + approx_json_bytecnt(k) + approx_json_bytecnt(v)
        return bytecnt
    elif isinstance(data, str):
        # '"' + UTF8 string + '"'
        # but also double count newline and backslash for escapes
        return 2 + len(data.encode('utf8')) + data.count('\n') + data.count('\\') + data.count('"')
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
        if nrows < 0:
            nrows = 0
            break
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
def insert_table_rows(catalog, schema_name, table_name, payload, defaults=None, batch_size=10000, batch_bytes=2000000, onconflict=None, decrement=1000):
    """Insert rows into the specified ermrest table

    Args:
        catalog (obj): Deriva ERMrest catalog
        schema_name (str): schema name of the table to delete rows from
        table_name (str): table name to delete rows from
        payload (list): the rows to be inserted
        defaults (list): a list of default columns to be filled by ERMrest
        batch_size (int): the targeted number of rows per batch
        batch_bytes (int): the batch byte limit. If the batch content exceeds batch_bytes limit, the number of rows is reduced
    until the content fits within the limit.
        onconflict (str): what to do if rows already exist. By default, ERMrest will throw an error. Set it to "skip"
    to avoid the error.
    """
    
    if not payload:
        return []

    query_params = []
    if onconflict:
        query_params.append('onconflict=%s' % (urlquote(onconflict)))
    if defaults:
        query_params.append('defaults=%s' % (','.join(list(map(urlquote, defaults)))))
    query_str = '?%s' % ('&'.join(query_params)) if query_params else ''

    inserted = []
    index = 0
    nrows = batch_size
    payload_len = len(payload)
    print("** insert_if_not_exist: %s:%s payload len: %d rows (%d bytes)" % (schema_name, table_name, payload_len, approx_json_bytecnt(payload)))
    
    while index < payload_len:
        """# old implementation
        #nrows = batch_size  # old implementation
        batch = payload[index:index+nrows]
        bytes = approx_json_bytecnt(batch)
        while bytes > batch_bytes:
            nrows = nrows - 1000
            batch = payload[index:index+nrows]            
            bytes = approx_json_bytecnt(batch)
        if nrows <= 0: nrows = 1
        """
        nrows = get_batch_len(payload, index=index, batch_size=batch_size, batch_bytes=batch_bytes, decrement=decrement)
        
        batch = payload[index:index+nrows]
        #print("index=%d nrows=%d bytes=%d" % (index, nrows, bytes))
        resp = catalog.post(
            "/entity/%s:%s%s" % (urlquote(schema_name), urlquote(table_name), query_str),
            json=batch
        )
        inserted.extend(resp.json())
        #print("inserting rows[%d:%d](%d bytes): %s:%s => \n%s " % (index, nrows, bytes, schema_name, table_name, json.dumps(resp.json(), indent=4, sort_keys=True)))        
        #print("  - inserting rows[%d:%d](%d bytes): %s:%s " % (index, index+nrows, bytes, schema_name, table_name))
        index = index + nrows

    return(inserted)

# ---------------------------------------------------------------
def insert_rows_if_not_exist(catalog, schema_name, table_name, payload, defaults=None, batch_size=10000, batch_bytes=2000000):
    """insert rows into specified table. Skip rows that already exist.
    This function call insert_table_rows with onconflict="skip".
    
    See the function signature from insert_table_rows. 
    """
    return insert_table_rows(catalog, schema_name, table_name, payload, defaults=defaults, batch_size=batch_size, batch_bytes=batch_bytes, onconflict="skip")

# ---------------------------------------------------------------
def update_table_rows(catalog, schema_name, table_name, model=None, keys=["RID"], column_names=None, payload=None, batch_size=10000, batch_bytes=2000000, decrement=1000):
    """
    Passing model object to remove one roundtrip time for getCatalogModel request.

    Args:
        model (obj): Deriva ERMrest model. This positional argument used to be catalog. For backward compatibility,
    this is also allowed, but the model will be fetched from the server every time this is called (not efficient). 
        schema_name (str): schema name of the table to delete rows from
        table_name (str): table name to delete rows from
        model (obj): ERMrest model object. If not provided, we will fetch it from the ERMrest catalog.
        keys (list): the key columns to use for updates
        column_names (list): the name of columns to be updated. If None, all applicable columns will be updated
        payload (list): the rows to be updated
        batch_size (int): the targeted number of rows per batch
        batch_bytes (int): the batch byte limit. If the batch content exceeds batch_bytes limit, the number of rows is reduced
    until the content fits within the limit.
    
    """
    if isinstance(catalog, Model):
        model = catalog
        catalog = model.catalog
    elif isinstance(catalog, ErmrestCatalog):
        if not model: model = catalog.getCatalogModel()        
    else:
        raise TypeError("Incorrect data type. The first argument is expected to be either Model or ErmrestCatalog")
    
    if not payload:
        return []
    
    # if updaed_cname is NULL, use all columns except system columns
    if not column_names:
        column_names = []
        update_exclude_columns = keys + ["RID", "RCT", "RMT", "RCB", "RMB"]            
        for cname in  model.schemas[schema_name].tables[table_name].columns.elements:
            if cname not in update_exclude_columns:
                column_names.append(cname)
    cnames = ','.join([ urlquote(str(c)) for c in column_names])
    if not cnames:
        logger.warning("WARNING: column names to be updated is empty")
        return []
    
    updated = []
    index = 0
    nrows = batch_size
    payload_len = len(payload)
    print("** update_table: %s:%s payload len: %d rows (%d bytes)" % (schema_name, table_name, payload_len, approx_json_bytecnt(payload)))
    
    while index < payload_len:
        """
        nrows = batch_size  # reset nrows
        batch = payload[index:index+nrows]
        bytes = approx_json_bytecnt(batch)
        while bytes > batch_bytes and nrows > 1:  # TODO: better backoff algorithm
            nrows = max(1, nrows - 1000)
            batch = payload[index:index+nrows]            
            bytes = approx_json_bytecnt(batch)
        """
        nrows = get_batch_len(payload, index=index, batch_size=batch_size, batch_bytes=batch_bytes, decrement=decrement)
            
        #print("- updating rows[%d:%d](%d bytes): %s:%s => \n%s " % (index, nrows, bytes, schema_name, table_name, json.dumps(batch, indent=4, sort_keys=True)))
        resp = catalog.put(
            "/attributegroup/%s:%s/%s;%s" % (urlquote(schema_name), urlquote(table_name), ','.join([ urlquote(k) for k in keys ]), cnames),
            json=batch
        )
        updated.extend(resp.json())
        print("  - updated rows[%d:%d](%d bytes): %s:%s " % (index, index+nrows, bytes, schema_name, table_name))
        index = index + nrows


    return(updated)

# ---------------------------------------------------------------
def get_key_for_dict(keys, row):
    """DEPRECATED"""
    if len(keys) == 1:
        return(row[keys[0]])
    index = []
    for key in keys:
        index.append(row[key])
    return(tuple(index))


def get_key_values(row, key_cnames):
    """
    Return key value(s) from a row based on specified key column names.
    
    Args:
        row (dict): A dictionary representing a single database row.
        key_cnames (list): A list of key column names.
        
    Returns:
        The column value of the single key column, or a tuple of all column values 
        in the column list if multiple keys are provided.
    """
    if not key_cnames:
        raise ValueError("a list of key column names are needed")
    
    if len(key_cnames) == 1:
        return row[key_cnames[0]]
    else:
        values = [ row[cname] for cname in key_cnames ]
        
    return tuple(values)


# ---------------------------------------------------------------
def upsert_table_rows(model, sname, tname, payload, existing_key2rows, keys=None, exclude_cnames=None, exclude_rows=None,
                      update_existing=True, defaults=None, verbose=False, dry_run=False, update_only=False):
    """
    Check rows in payload against existing ermrest entries provided. If any of the column values of a row is different,
    add the row to the update list. The function returns ermrest rows that have been updated.
        
    Args:
        model (obj): ermrest model
        sname (str): schema name of the table to have its rows updated
        tname (str): table name of the table to have its rows updated
        payload (list): the updating rows
        existing_keys2rows (dict): the key-to-row dict of the existing rows for checking whether the content has changed
        keys (list): a key cname list associated with exiting_keys2rows key
        exclude_cnames (list): column names to be excluded from update    
        exclude_rows (list): rows to be excluded, matched by the same `keys` used for the payload lookup
                             (e.g. rows that were just inserted and should not be updated again).
        update_existing (boolean): If update_existing flag is set, the existing_key2rows dict will also be updated.
        dry_run (boolean): if set, log the rows that would be updated (WARNING) and return an empty list without writing to Ermrest.

    Returns:
        list: a list of rows that have been updated in Ermrest, empty when nothing was modified or when dry_run is set
    """

    if keys is None: keys = ["RID"]
    if exclude_cnames is None: exclude_cnames = []
    if exclude_rows is None: exclude_rows = []
    if not payload: return []

    catalog = model.catalog    
    table = model.schemas[sname].tables[tname]
    
    exclude_key_values = [ get_key_values(row, keys) for row in exclude_rows ]  # exclude key values
    exclude_columns = set( ["RID", "RCT", "RMT", "RCB", "RMB"] + keys + exclude_cnames )
    update_columns = set(model.schemas[sname].tables[tname].columns.elements) - set(exclude_columns)
    update_columns = list( update_columns & set(payload[0].keys()) )  # intersection of payload and existing rows

    inserting = inserted = []
    updating = updated = []
    for row in payload:
        key_val = get_key_values(row, keys)
        existing_row = existing_key2rows.get(key_val, None)
        if not existing_row:
            inserting.append(row)
            continue
        #if "RID" not in row.keys(): row["RID"] = existing_row["RID"] # not needed
        if key_val in exclude_key_values: continue
        # -- check whether the row values have changed
        for cname in update_columns:
            if cname not in existing_row.keys() or cname not in row.keys() : continue
            ctype = table.columns[cname].type.typename
            if ctype == "timestamptz" and row[cname] and existing_row[cname] and timestamptz_to_datetime(row[cname]) == timestamptz_to_datetime(existing_row[cname]): continue
            if row[cname] != existing_row[cname]:
                if verbose: print("----- cname: %s, ctype: %s : %s v.s. %s (existing) are different" % (cname, ctype, row[cname], existing_row[cname]))
                updating.append(row)
                break

    if inserting:
        if update_only:
            logger.error("* upsert_table_rows: Non-existing rows in table %s: %d rows do not exist: %s" % (tname, len(inserting), json.dumps(inserting[0:2], indent=4)))
            raise Exception("Non-existing rows in table %s: %d rows do not exist" % (tname, len(inserting)))
        if dry_run:
            logger.warning("** upsert_table_rows [DRY RUN] : %s - inserting %d rows: %s", tname, len(inserting), json.dumps(inserting[0:2], indent=4))
        else:
            inserted = insert_table_rows(catalog, sname, tname, inserting, defaults=defaults, onconflict="skip")
            if verbose: print("- upsert_table_rows: %s - INSERTED %d rows: %s" % (tname, len(inserted), json.dumps(inserted[0:2], indent=4)))
        
    if updating:
        if dry_run:
            logger.warning("** upsert_table_rows [DRY RUN] : %s - updating %d rows: %s", tname, len(updating), json.dumps(updating[0:2], indent=4))
        else:
            if verbose: print("- upsert_table_rows: %s - updating %d rows: %s" % (tname, len(updating), json.dumps(updating[0:2], indent=4)))
            updated = update_table_rows(model, sname, tname, keys=keys, payload=updating, column_names=update_columns)
            if verbose: print("- upsert_table_rows: %s - UPDATED %d [from %d] rows: %s" % (tname, len(updated), len(payload), json.dumps([ existing_key2rows[get_key_values(row, keys)] for row in updating[0:1] ] , indent=4)))        
    else:
        if verbose: print("x upsert_table_rows: %s -- no rows to update (from %d)" % (tname, len(payload)))
        pass

    if update_existing:
        for row in inserted:
            existing_key2rows[get_key_values(row, keys)] = row
        for row in updated:
            existing_key2rows[get_key_values(row, keys)].update(row)
        
    return inserted+updated


# ---------------------------------------------------------------
# Example of response object: statis_code=204 headers={'Date': 'Fri, 27 Sep 2024 19:36:32 GMT', 'Server': 'Apache/2.4.59 (Fedora Linux) OpenSSL/3.0.9 mod_wsgi/4.9.4 Python/3.11', 'Set-Cookie': 'webauthn_track=ef32ad10.6231ef8ef6959; path=/; expires=Sat, 27-Sep-25 19:36:32 GMT', 'Vary': 'DNT,cookie,accept,User-Agent', 'Upgrade': 'h2', 'Connection': 'Upgrade, Keep-Alive', 'ETag': '"FvbI_TUNoSPPd3ANOP6-Ew==;*/*;2024-09-27 12:36:32.975696-07:00"', 'Keep-Alive': 'timeout=5, max=100'}

def delete_table_rows(catalog, schema_name, table_name, constraints=None, key="RID", values=None, verbose=False, dry_run=False):
    """
    Delete table rows according to the provided constraints.

    Args: 
        catalog (obj): Deriva ERMrest catalog
        schema_name (str): schema name of the table to delete rows from
        table_name (str): table name to delete rows from
        constraints (str): constraints of rows to be deleted. 
        key (str): the key column participating in the cosntraints
        values (str): values of the key to be deleted.
        verbose (bool): whether to print progress to stdout
        dry_run (bool): print out the details of the delete intention without actually submitting the request to the server
    
    Note: To be conservative, either the constraint is provided or key and values are provided. 
    To delete all rows, set constraints="RID::regexp::*"
    
    TODO: address multi-column keys
    """
    #print("sname: %s, tname: %s, constraints: %s, key:%s, values:%s" % (schema_name, table_name, constraints, key, values))
    
    # no constraint will cause all rows to be deleted!!
    if (not values or not key) and (not constraints):
        raise ValueError("DELETE ERROR: delete_table_rows requires either constraints or key/values of rows to be deleted")
    
    # prioritize key values.
    if key and values:
        constraints = "%s=ANY(%s)" % (urlquote(str(key)), ",".join([ urlquote(str(v)) for v in values ]))
    try:
        url = "/entity/M:=%s:%s/%s" % (urlquote(schema_name), urlquote(table_name), constraints)
        if not dry_run:
            resp = catalog.delete(url)
            if verbose: print("delete_table_rows: %s: status_code: %s, headers: %s" % (url, resp.status_code, resp.headers))
        else:
            print(f"- delete_table_rows DRY_RUN with url: {url}") 
    except requests.HTTPError as e:
        if getattr(e, 'response', None) is not None and e.response.status_code == 404:            
            logger.info("delete_table_rows: ROWS NOT FOUND: url:%s status_code=%s NOT FOUND" % (url, e.response.status_code))
        else:
            logger.error("ERROR happens during delete_table_rows: url:%s, errors=%s" % (url, e))
            raise 

# ---------------------------------------------------------------
def _key_constraint_term(keys, kval):
    """URL-encoded constraint term for one key value: `v` for a single key, `k1=v1&k2=v2` for multi-key."""
    if len(keys) == 1:
        return urlquote(str(kval))
    return '&'.join(f"{urlquote(str(k))}={urlquote(str(v))}" for k, v in zip(keys, kval))


def _key_constraints(keys, terms):
    """Join encoded terms into an ERMrest constraint: `k=any(t1,t2)` (single key) or `t1;t2` (multi-key)
    where t is `v` in a single key, and `k1=v1&k2=v2` in multi-keys
    """
    if len(keys) == 1:
        return f"{urlquote(str(keys[0]))}=any({','.join(terms)})"
    return ';'.join(terms)


def get_batch_size_by_str_length(keys, kvals, start_index, length_limit=None):
    """ Get batch size based on key column names and values with a starting index that fits
    within the string length limit (e.g. URL length limitation). This function is used
    to split a long server API that would have failed into many smaller requests that fit
    the length limitation.
    
    Args
        keys (list): key column names
        kvals (list): a list of key values if key length = 1 else a list of key column value tuples
        start_index (int): the index of kvals to use as the start of the payload
        length_limit (int): string length limit

    constraint formats:
        single key: <keys[0]>=any(...) format
        multi key columns: <keys[0]>=<kvals[i][0]>&<keys[1]>=<kvals[i][1];...
    """
    
    if not length_limit: length_limit=URL_LENGTH_LIMIT
    if start_index >= len(kvals): return 0

    # fixed part of the constraint: "<key>=any()" for a single key, nothing for multi-key
    current_length = len(_key_constraints(keys, [])) if len(keys) == 1 else 0
    index = start_index
    while index < len(kvals):
        separator = 1 if index > start_index else 0   # "," (single key) or ";" (multi-key)
        added = separator + len(_key_constraint_term(keys, kvals[index]))
        if current_length + added > length_limit:
            break
        current_length += added
        index += 1
        
    batch_size = max(index - start_index, 1)
    #print("- get_batch_size_by_str_length: batch_size: %d, length: %d" % (batch_size, l))
    
    return batch_size


def delete_table_rows_by_keys(catalog, sname, tname, keys, key_values, length_limit=None, dry_run=True, verbose=False):
    """Delete sample with the specified RIDs from sample table in batches (due to URL length limitation and response time).
    Note: Deleting rows will also delete db indices which could leads to server server timeout if the payload is too large.
    
    Args:
        catalog (obj): Deriva ERMrest catalog
        sname (str): schema name of the table to delete rows from
        tname (str): table name to delete rows from
        keys (list): key column names
        kvals (list): a list of key values if key length = 1 else a list of key column value tuples
        length_limit (int): API string length limit
        dry_run (bool): print out the details of the delete intention without actually submitting the request to the server    
        verbose (bool): whether to print progress to stdout
    """
    
    if not key_values: return
    if len(keys) > 1 and len(key_values[0]) != len(keys):
        raise ValueError(f"INPUT_ERROR: len of key ({len(keys)}) and values ({len(key_values[0])}) are not the same")
    
    if verbose: print(f"- delete_table_rows_by_keys: {tname} - deleting [n={len(key_values)}][0:5]: {key_values[0:5]}")

    if not length_limit: length_limit = URL_LENGTH_LIMIT
    index = 0
    total = len(key_values)
    while index < total:
        batch_size = get_batch_size_by_str_length(keys, key_values, index, length_limit)
        if verbose: print("  - delete_table_rows_by_keys: index: %d, batch_size: %d" % (index, batch_size))
        kvals = key_values[index:index+batch_size]
        # built with the same helpers get_batch_size_by_str_length measures, so the two cannot drift apart
        constraints = _key_constraints(keys, [ _key_constraint_term(keys, kval) for kval in kvals ])
        delete_table_rows(catalog, sname, tname, constraints=constraints, dry_run=dry_run, verbose=verbose)
        index += batch_size
    

# ---------------------------------------------------------------

# assignment has to happen with alias
def urlquote_list(attr_list):
    quoted_list = []
    for attr in attr_list:
        # aggregate function e.g. Agg:=array(M:structure_id)
        m = re.search("^([^:=]+:=)?(array|array_d|cnt|cnt_d|min|max)+\\(([^:=]+:)*([^:=()]+)\\)$", attr)
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
def get_ermrest_query(catalog, schema_name, table_name, constraints=None, keys=["RID"], attributes=None, aggregates=None, sort=["RID"], limit=None, batch_size=5000):
    """
    Args:
        catalog (obj): catalog
        schema_name (str): schema name for ermrest API
        table_name (str): table name for ermrest API. This table will also be assigned an alias M
        constraints (str): constraint str for ermrest API
        keys (list): a list of keys to be used for attributegroup API
        attributes (list): a list of attributes for attributegroup API
        aggregates (list): a list of aggretates for aggregate API
        sort (list): sort columns
    
    TODO: address sort (to support direction) and after
    """
    payload = []
    if not limit:
        limit = 10000000
    after = []
    while True:
        page_size = limit if limit < batch_size else batch_size
        # -- base api
        api = "attributegroup" if attributes else "aggregate" if aggregates else "entity"
        url = "/%s/M:=%s:%s" % (api, urlquote(schema_name), urlquote(table_name))
        if constraints: url = "%s/%s" % (url, constraints)
        # -- key/attr list
        if attributes:
            quoted_keys = urlquote_list(keys)
            quoted_list = urlquote_list(attributes)
            if quoted_keys == quoted_list:
                url = "%s/%s" % (url, ",".join(quoted_keys))  # get key only
            else:
                url = "%s/%s;%s" % (url, ",".join(quoted_keys), ",".join(quoted_list))
        elif aggregates:
            quoted_list = urlquote_list(aggregates)                
            url = "%s/%s" % (url, ",".join(quoted_list))
        # -- sort
        if api not in ["aggregate"]:
            if sort:
                url = "%s@sort(%s)" % (url, ",".join(urlquote_list(sort)))
            if after:
                url = "%s@after(%s)" % (url, ",".join( [ urlquote(v) for v in after ]))
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
# This is needed by PDB
def get_key2rows(catalog, schema_name, table_name, constraints='', keys=["RID"], attributes=None, sort=["RID"], limit=None):
    """ Create a key2rows dict based on provided key columns.
    If keys is a single column, then a string is used for key, else a tuple of values corresponding to
    key columns are used for the return dict keys
    
    """
    key2rows = {}
    rows = get_ermrest_query(catalog, schema_name, table_name, constraints=constraints, keys=keys, attributes=attributes, sort=sort, limit=limit)
    # strip alias from keys 
    dict_keys = [ k.rsplit(":", 1)[1] if len(k.rsplit(":", 1)) == 2 else k for k in keys ]
    if len(dict_keys) == 1:
        key2rows = { row[dict_keys[0]]: row for row in rows  }
    elif len(dict_keys) > 1:
        key2rows = { tuple([row[k] for k in dict_keys ]): row for row in rows  }
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
