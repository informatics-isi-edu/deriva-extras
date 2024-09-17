#!/usr/bin/python

import sys
import json
from deriva.core import ErmrestCatalog, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey
from deriva.core import urlquote, urlunquote, DEFAULT_SESSION_CONFIG

import argparse

# -- define ddctx cid string
# 
DCCTX = {
    "model": "model/change",
    "acl" : "config/acl",
    "data": "data",
    "annotation" : "config/anno",
    "comment" : "config/comment",
    "pipeline" : "pipeline",
    "pipeline/image" : "pipeline/image",
    "pipeline/seq/scrna" : "pipeline/seq/scrna",
    "pipeline/seq/mrna" : "pipeline/seq/mrna",
    "pipeline/seq/st" : "pipeline/seq/st",    # spatial transcriptomics
    "pipeline/noid" : "pipeline/noid",        # obsolete
    "cli": "cli",
    "cli/read" : "cli/read",
    "cli/test": "cli/test",            # read-write    
    "cli/ingest": "cli/ingest",        # read-write
}


