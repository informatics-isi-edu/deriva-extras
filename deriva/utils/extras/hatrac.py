#!/usr/bin/python

import sys
import json
import re
import requests.exceptions
from deriva.core import ErmrestCatalog, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey, tag, AttrDict
from deriva.core import urlquote, urlunquote
from deriva.core.utils.hash_utils import compute_file_hashes compute_hashes

# ===================================================================================

# content disposition can only contain:  - _ . ~ A...Z a...z 0...9 or %
def sanitize_filename(filename):
    new_name = re.sub(r"[^-_.~A-Za-z0-9%]", "_", filename)
    return new_name

# ----------------------------------------------------------

def hex_to_base64(hstr):
    data = binascii.a2b_hex(hstr.strip())
    return binascii.b2a_base64(data).decode('utf-8').strip()

# ----------------------------------------------------------
def base64_to_hex(b64str):
    data = binascii.a2b_base64(b64str)
    return binascii.b2a_hex(data).decode('utf-8').strip()

# ----------------------------------------------------------
"""
# -- doesn't really work
def hexstr2base64(hstr):
    data = binascii.a2b_hex(hstr)
    base64 = re.match("b'(.*)'", binascii.b2a_base64(data).strip())[1]
    return base64
"""

# ===================================================================================
'''
header keys are: ['Date', 'Server', 'WWW-Authenticate', 'Vary', 'Upgrade', 'Connection', 'Content-Length', 'accept-ranges', 'content-md5', 'Content-Location', 'content-disposition', 'ETag', 'Keep-Alive', 'Content-Type']
'''
def get_hatrac_metadata(store, object_path):
    # this requires more authn, I think
    #resp = store.get('%s;metadata/' % object_path)
    #md1 = resp.json()

    # this works if you can read the object
    try:
        resp = store.head(object_path)
    except requests.HTTPError as e:
        #print("ERROR: e.response=%s" % (e.response))
        return None
            
    md = { k.lower(): v for k, v in resp.headers.items() }
    #print("get_hatrac_metadata: md: %s" % (json.dumps(md, indent=4)))
    if "content-disposition" in md.keys():
        matches = re.match("^filename[*]=UTF-8''(?P<name>.+)$", md["content-disposition"])
        md["filename"] = matches.groupdict()["name"]
    md["server_uri"] = store._server_uri
    md["caching"] = store._caching
    
    return md

# ===================================================================================

def get_hatrac_file(store, file_url, destination_file_path):
    """
    Download hatrac file
      :param file_url: hatrac url
      :param destination_file_path: the file path where the hatrac object will be saved as
    """
    resp = store.get_obj(file_url, destfilename=dest_file_path)
    close(resp)

# ----------------------------------------------------------
def put_small_hatrac_obj(store, file_url, file_path, file_name, md5_base64):
    """
    Only works for smaller file size (<=25MB)
    """
    hatrac_url = to_store.put_obj(file_url, file_path, md5=md5_base64, sha256=None, parents=True, content_type=None,
                                  content_disposition="filename*=UTF-8''%s" % (file_name),
                                  allow_versioning=True)
    return hatrac_url

# ----------------------------------------------------------

# ----------------------------------------------------------    
# TODO: This is incomplete. DO NOT USE. Use store.put_loc for now.
# e.g. hatrac_url = store.put_loc(upload_file_url, file_path, md5=md5_base64,content_disposition="filename*=UTF-8''%s" % (file_name), chunked=True, chunk_size=10*1024*1024, allow_versioning=False)

def hatrac_upload(store,
                  path,
                  file_path,
                  file_name = None,
                  headers=DEFAULT_HEADERS,
                  md5=None,
                  sha256=None,
                  content_type=None,
                  content_disposition=None,
                  chunked=True,
                  chunk_size=DEFAULT_CHUNK_SIZE,
                  create_parents=True,
                  allow_versioning=True,
                  callback=None,
                  cancel_job_on_error=True):
    """
        :param path:
        :param file_path:
        :param headers:
        :param md5:
        :param sha256:
        :param content_type:
        :param content_disposition:
        :param chunked:
        :param chunk_size:
        :param create_parents:
        :param allow_versioning:
        :param callback:
        :param cancel_job_on_error:
        :return:
    """

    if not os.path.isfile(file_path):
        raise Exception("FILE_NOT_FOUND: file %s doesn't exist" % (file_path))
    if md5:
        md5_base64 = md5
        md5_hex = base64_to_hex(md5_base64)
    else:
        f = open(file_path, "rb")
        (md5_hex, md5_base64) = compute_hashes(f)["md5"]
        f.close()

    file_bytes = os.stat(file_path).st_size
    file_name = os.path.basename(file_path) if not file_name else file_name        
    file_name = sanitize_filename(file_name)
    if not content_disposition:
        content_disposition="filename*=UTF-8''%s" % (file_name)
    hatrac_url = store.put_loc(
        path,
        file_path,
        headers=headers,
        md5=md5_base64,
        sha256=sha256,
        content_type=content_type,
        content_disposition=content_disposition,
        chunked=chunked,
        chunk_size=chunk_size,
        create_parents=create_parents,
        allow_versioning=allow_versioning,
        callback=callback,
        cancel_job_on_error=cancel_job_on_error,
    )

    return (hatrac_url, file_name, file_bytes, md5_hex, sha256)

# --------------------------------------------------------------------------------

def upload_file(from_store, to_store, row, c_name, c_url, c_md5, c_bytes):
    # if the url is not in hatrac, return. Don't know how to handle
    if not row[c_url] or not re.match("^/hatrac/", row[c_url]):
        return None
    try:
        to_properties = get_hatrac_metadata(to_store, row[c_url])
        if to_properties["content-md5"] == row[c_md5]:
            return row
    except Exception as e:
        pass
    
    #from_store_name = re.match("https://(.*)$", from_store.get_server_uri())[1]    
    #to_store_name = re.match("https://(.*)$", to_store.get_server_uri())[1]
    rid = row["RID"]
    file_url = row[c_url]
    properties = get_hatrac_metadata(from_store, file_url)    
    if not row[c_name]:
        if ("content-type" in properties.keys() and properties["content-type"] == 'image/jpeg') or c_name == "Thumbnail_File":
            file_ext = ".jpg"
        else:
            file_ext = ""
        row[c_name] = "%s_%s%s" % (rid, re.match("(.*)_(File|Name)$", c_name)[1], file_ext)
        print("- WARNING: %s is missing. Will assign %s" % (c_name, row[c_name]))
    file_name = sanitize_filename(row[c_name])
    file_path = "%s/%s_%s" % (processing_dir, rid, file_name)
    md5_hex = row[c_md5]
    md5_base64 = hex_to_base64(md5_hex)
    file_mb = int(row[c_bytes])/(1024*1024)
    file_url_base = re.match("^([^:]+)", file_url)[1]    
    print("  -- rid: %s, name: %s, url: %s, path: %s, md5_hex: %s, md5_base64: %s bytes: %.2f MiB --" % (rid, file_name, file_url, file_path, md5_hex, md5_base64, row[c_bytes]/(1024*1024)))

    local_resp = from_store.get_obj(file_url, destfilename=file_path)

    try:
        if "content-encoding" in properties.keys():
            # one option is not to check
            #md5_base64 = None # don't check
            raise Exception("ERROR: content-encoding is not expected")
        else:
            if "content-md5" not in properties.keys():
                print("  - ERROR: MISSING MD5: %s -> %s " % (from_store._server_uri, json.dumps(properties, indent=4)))
            elif properties["content-md5"] != md5_base64:
                print("  - ERROR: INCORRECT ERMrest entry [%s]: %s instead of %s" % (c_md5, properties["content-md5"], md5_base64))
                md5_base64 = properties["content-md5"]
                md5_hex = base64_to_hex(md5_base64)
                row[c_md5] = md5_hex
            if "content-length" in properties.keys() and int(properties["content-length"]) != row[c_bytes]:
                print("  - ERROR: INCORRECT ermrest entries [%s]: %s instead of %s" % (c_bytes, properties["content-length"], row[c_bytes]))
                row[c_bytes] = int(properties["content-length"])
            
            hatrac_url = to_store.put_loc(file_url_base, file_path, md5=md5_base64, content_disposition="filename*=UTF-8''%s" % (file_name),
                                          chunked=True, chunk_size=chunk_size)
            row[c_url] = hatrac_url
    except Exception as e:
        row = None
        print("%s" % (e))
    finally:
        local_resp.close()
        clean_up(processing_dir)    
    return(row)

# --------------------------------------------------------------------------------
def copy_file(from_store, to_store, row, c_name, c_url, c_md5, c_bytes):
    """
    copy hatrac file from one store to another store
    """
    upload_file(from_store, to_store, row, c_name, c_url, c_md5, c_bytes)
    
# ===================================================================================


# ===========================================================================

if __name__ == "__main__":
    cli = BaseCLI("extras", None, 1)
    cli.parser.add_argument('--catalog-id', metavar="<catalog_id>", help="catalog-id", default="99")
    args = cli.parse_cli()
    print(args)
    
    credentials = get_credential(args.host, args.credential_file)
    catalog = ErmrestCatalog("https", args.host, args.catalog_id, credentials)
    catalog.dcctx['cid'] = "cli/test"
    store = HatracStore("https", args.host, credentials)


