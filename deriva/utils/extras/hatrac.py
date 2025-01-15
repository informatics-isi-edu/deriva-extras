#!/usr/bin/python

import sys
import json
import re
import requests.exceptions
import os
from dataclasses import dataclass
import mimetypes

from deriva.core import ErmrestCatalog, HatracStore, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey, tag, AttrDict
from deriva.core import urlquote, urlunquote
from deriva.core.utils.hash_utils import compute_file_hashes, compute_hashes
from deriva.core.utils.core_utils import DEFAULT_CHUNK_SIZE, DEFAULT_HEADERS

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

# ----------------------------------------------------------
def get_hatrac_metadata(store, object_path):
    """
    Get hatrac metadata through head request
    Header keys: ['Date', 'Server', 'WWW-Authenticate', 'Vary', 'Upgrade', 'Connection', 'Content-Length', 'accept-ranges', 'content-md5', 'Content-Location', 'content-disposition', 'ETag', 'Keep-Alive', 'Content-Type']
    Additional keys added: ['filename', 'server-uri', 'caching']
    """
    
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
    md["server-uri"] = store._server_uri
    md["caching"] = store._caching
    
    return md

# ===================================================================================
@dataclass
class HatracFile:
    """

    """
    store: HatracStore
    upload_url: str = None # url path e.g. "/hatrac/path/to/file"
    hatrac_url: str = None# versioned hatrac url returned after uploading to hatrac e.g. "/hatrac/path/to/file:version"
    file_path: str = None
    file_name: str = None
    file_bytes: int = None
    md5_hex: str = None
    md5_base64: str = None
    sha256_hex: str = None
    sha256_base64: str = None
    content_type: str = None
    default_content_type: str = 'application/octet-stream'
    chunk_size: int = 25*1024*1024

    # ------------------------------------------------------------------        
    def upload_file(self, fpath, upload_url, file_name=None, hashes=["md5"], content_type=None, verbose=False):
        """
        upload_file prepares file related metadata, upload the file to hatrac, and store the versioned hatrac url in the structure.
        TODO: add setting content-type logic. With s3, hatrac's guess of content-type is limited
        """
        self.file_path = fpath        
        if not self.file_path:
            raise Exception("UPLOAD ERROR: A local file path needs to be specified")
        if not os.path.isfile(self.file_path): 
            raise Exception("UPLOAD ERROR: A local file path [%s] is not a file or doesn't exist" % (self.file_path))
        self.upload_url = upload_url
        self.file_name = os.path.basename(self.file_path) if not file_name else file_name        
        self.file_name = sanitize_filename(self.file_name)
        self.file_bytes = os.path.getsize(self.file_path) #os.stat(self.file_path).st_size
        if "md5" in hashes:
            (self.md5_hex, self.md5_base64) = compute_file_hashes(self.file_path, hashes=['md5'])['md5']
        if "sha256" in hashes:
            (self.sha256_hex, self.sha256_base64) = compute_file_hashes(self.file_path, hashes=['sha256'])['sha256']
        if not mimetypes.inited: mimetypes.init()
        self.content_type = mimetypes.guess_type(self.file_name)[0]
        
        if verbose: print("upload: fpath: %s, url: %s, content_type: %s" % (self.file_path, self.upload_url, self.content_type))
        content_disposition="filename*=UTF-8''%s" % (self.file_name)
        #hatrac_url = self.store.put_obj(upload_file_url, file_path, md5=md5_base64, content_disposition="filename*=UTF-8''%s" % (file_name), allow_versioning=False)
        self.hatrac_url = self.store.put_loc(self.upload_url, self.file_path, md5=self.md5_base64, content_disposition=content_disposition, content_type=self.content_type, chunked=True, chunk_size=self.chunk_size, allow_versioning=False)
        
    # ------------------------------------------------------------------    
    def download_file(self, hatrac_url, destination_dir, file_name=None, hashes=[], verbose=False):
        """
        Download file from hatrac_url and put it under destination_dir/file_name.
        file_name is derived from 1) file_name argument, 2) file_name seted in hatrac content disposition, 3) hatrac_url, respectively. 
        Hashes specified in hashes argument will be computed after the file is downloaded.
        """
        if not os.path.isdir(destination_dir): 
            raise Exception("DOWNLOAD ERROR: A local directory [%s] is doesn't exist" % (destination_dir))
        if not hatrac_url.startswith("/hatrac/"):
            raise Exception("DOWNLOAD ERROR: url [%s] is not a hatrac url" % (hatrac_url))
        self.hatrac_url = hatrac_url
        if file_name:
            self.file_name = file_name
        else:
            md = get_hatrac_metadata(self.store, hatrac_url)
            self.content_type = md['content-type']
            if "filename" in md.keys():
                self.file_name = md["filename"]
            else:
                self.file_name = self.hatrac_url.rsplit("/", 1)[1].rsplit(":", 1)[0]
        self.file_path = "%s/%s" % (destination_dir, self.file_name)
        # Note: if self.file_path is not null and hatrac provides md5, the file is hash-verified.
        self.store.get_obj(self.hatrac_url, destfilename=self.file_path)
        self.file_bytes = os.path.getsize(self.file_path) #os.stat(self.file_path).st_size        
        if "md5" in hashes:
            (self.md5_hex, self.md5_base64) = compute_file_hashes(self.file_path, hashes=['md5'])['md5']
        if "sha256" in hashes:
            (self.sha256_hex, self.sha256_base64) = compute_file_hashes(self.file_path, hashes=['sha256'])['sha256']
        if verbose:
            print("download: fpath: %s, url: %s, content_type: %s, md5: %s" % (self.file_path, self.hatrac_url, self.content_type, self.md5_hex))
    
    # ------------------------------------------------------------------
    def verify(self, file_bytes=None, md5=None, sha256=None):
        """
        verify download hatrac file against provided arguments. 
        """
        if file_bytes:
            assert self.file_types == file_bytes, "Mismatched file bytes: %s vs %s" % (self.file_bytes, file_bytes)
        if md5: 
            assert self.md5_hex == md5, "Mismatched md5: %s vs %s" % (self.md5_hex, md5)        
        if sha256: 
            assert self.sha256_hex == sha256, "Mismatched md5: %s vs %s" % (self.sha256_hex, sha256)
        

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
    hstore = HatracStore("https", args.host, credentials)

    hf = HatracFile(hstore)
    hf.upload_file('/home/hongsuda/git/deriva-extras/deriva/utils/extras/test.txt', '/hatrac/dev/pdb/test/test3',  'test2.txt')
    print("hf: file_url: %s, file_path: %s, md5: %s\n" % (hf.hatrac_url, hf.file_path, hf.md5_hex))
    hf2 = HatracFile(hstore)    
    hf2.download_file('/hatrac/dev/pdb/test/test3', '/home/hongsuda/git/deriva-extras/deriva/utils/extras')
    print("hf2: file_url: %s, file_path: %s, md5: %s" % (hf2.hatrac_url, hf2.file_path, hf2.md5_hex))
