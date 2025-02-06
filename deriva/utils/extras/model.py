#!/usr/bin/python

import sys
import json
from deriva.core import ErmrestCatalog, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey
from deriva.core import urlquote, urlunquote
import argparse
import re

# -- annotation tag to name
tag2name = {}
for key, value in tag.items():
    tag2name[value] = key
tag2name['tag:isrd.isi.edu,2016:ignore'] = "ignore"

# group id to group name mapping.
ermrest_groups = {}

# annotation tages configured at per-schema annotation script
per_schema_annotation_tags = [
    tag["source_definitions"], tag["visible_columns"], tag["visible_foreign_keys"], tag["display"],
    tag["table_display"], tag["column_display"], tag["foreign_key"], tag["column_defaults"],
    tag["key_display"], tag["app_links"], tag["indexing_preferences"], tag["table_alternatives"],
]

# these tags are handled in per-tag script or in catalog_annotation.py
per_tag_annotation_tags = [
    tag['asset'], tag['google_dataset'], tag['viz_3d_display'], tag['bulk_upload'],
    tag['export'], tag['export_2019'], tag['export_fragment_definitions'],
    tag['generated'], tag['immutable'], tag['non_deletable'], tag['required'],
    tag["citation"],     
]
catalog_wide_annotation_tags = [tag["generated"], tag["immutable"], tag["non_deletable"], tag["required"]]

TEXT_ARRAY_COLUMNS = ["Alternate_IDs", "Synonyms", "Related_Synonyms", "Parent_IDs"],
MARKDOWN_COLUMNS = ["Notes"]
INT4_COLUMNS = []

# -- =================================================================================
# -- model changes utilities
# --

# add table if not exist or update if exist
def create_schema_if_not_exist(model, schema_name, schema_comment=None):
    if schema_name not in model.schemas:
        
        model.create_schema(Schema.define(schema_name, schema_comment))
        print('create schema %s' % (schema_name))

# ----------------------------------------------------------------

# Add table if not exist or update if exist
def create_table_if_not_exist(model, schema_name, tdoc):
    schema = model.schemas[schema_name]
    if tdoc["table_name"] not in schema.tables.keys():
        print('creating table %s:%s' % (schema_name, tdoc["table_name"]))
        schema.create_table(tdoc)

# ----------------------------------------------------------------

def drop_table_if_exist(model, schema_name, table_name):
    if schema_name not in model.schemas.keys():
        raise TypeError("ERROR: drop table: schema %s doesn't exist" % (schema_name))

    schema = model.schemas[schema_name]
    if table_name in schema.tables.keys():
        model.schemas[schema_name].tables[table_name].drop()
        print('Drop table %s:%s' % (schema_name, table_name))
    else:
        print("ERROR: drop table: table %s:%s doesn't exist" % (schema_name, table_name))

# ----------------------------------------------------------------
def create_column_if_not_exist(model, schema_name, table_name, column_def):
    if schema_name not in model.schemas.keys() or table_name not in model.schemas[schema_name].tables.keys():
        raise TypeError("ERROR: either schema %s or table %s doesn't exist" % (schema_name, table_name))
    
    table = model.schemas[schema_name].tables[table_name]
    cname = column_def["name"]
    if cname not in table.columns.elements: 
        table.create_column(column_def)
        print('Create column %s:%s:%s' % (schema_name, table_name, cname))
    
# ----------------------------------------------------------------
# Check that schema and table exist before dropping column
def drop_column_if_exist(model, schema_name, table_name, column_name):
    if schema_name not in model.schemas.keys() or table_name not in model.schemas[schema_name].tables.keys():
        raise TypeError("ERROR: either schema %s or table %s doesn't exist" % (schema_name, table_name))
    
    table = model.schemas[schema_name].tables[table_name]
    if column_name in table.columns.elements:
        table.columns[column_name].drop()
        print('Drop column %s:%s:%s' % (schema_name, table_name, column_name))
    else:
        print("ERROR: drop column: column %s:%s:%s doesn't exist" % (schema_name, table_name, column_name))
        
# -------------------------------------------------------
def create_vocab_column_defs(cname_list):
    column_defs = []
    # add the rest of columns as text columns
    for cname in cname_list:
        if cname in TEXT_ARRAY_COLUMNS:
            ctype = builtin_types["text[]"]
        elif cname in MARKDOWN_COLUMNS:
            ctype = builtin_types.markdown
        elif cname in INT4_COLUMNS:
            ctype = builtin_types.int4
        else:
            ctype = builtin_types.text
            
        column_defs.append(
            Column.define(
                cname,
                ctype,
                nullok=True
            )
        )
        
    return(column_defs)

# -------------------------------------------------------

# Create a vocabulary table if it does not exixt
def create_vocab_tdoc(schema_name, table_name, table_comment, has_synnonyms, other_cnames=[], name_type="text"):
    
    column_defs = [
        Column.define(
            "Name",
            builtin_types[name_type],
            nullok=False
        )
    ]

    if has_synnonyms is True:
        column_defs.append(
            Column.define(
                "Synonyms",
                builtin_types['text[]'],
                nullok=True
            )
        )
    
    column_defs.append(
        Column.define(
            "Description",
            builtin_types.markdown,
            nullok=True
        )
    )

    if other_cnames:
        column_defs.extend(create_vocab_column_defs(other_cnames))
        
    key_defs = [
        Key.define(["RID"],
                   constraint_names=[[schema_name, table_name + "_RID_key"]]
                   ),
        Key.define(["Name"],
                   constraint_names=[[schema_name, table_name + "_Name_key"]]
                   )        
    ]
    
    fkey_defs = []
    
    table_def = Table.define(
        table_name,
        column_defs,
        key_defs=key_defs,
        fkey_defs=fkey_defs,
        comment=table_comment,
        provide_system=True
    )
    
    return table_def

# ----------------------------------------------------------------

# create a vocabulary table if it does not exixt
def create_vocabulary_tdoc(schema_name, table_name, table_comment, ID_prefix="isrd", URI_catalog_id=None, other_cnames=[]):

    # overwrite Description to be nullable
    if table_name in ['Species', 'Annotated_Term']:
        column_defs = [
            Column.define(
                "Description",
                builtin_types.markdown,
                nullok=True
            )
        ]
    else:
        column_defs = []
        
    if other_cnames: column_defs.extend(create_vocab_column_defs(other_cnames))
    
    key_defs = [
        Key.define(["RID"],
                   constraint_names=[[schema_name, table_name + "_RID_key"]]
                   ),
        Key.define(["ID"],
                   constraint_names=[[schema_name, table_name + "_ID_key"]]
                   ),
        Key.define(["Name"],
                   constraint_names=[[schema_name, table_name + "_Name_key"]]
                   ),
        Key.define(["Name", "ID"],
                   constraint_names=[[schema_name, table_name + "_Name_ID_key"]]
                   ),
        Key.define(["URI"],
                   constraint_names=[[schema_name, table_name + "_URI_key"]]
        )
    ]
    
    fkey_defs = []

    table_def = Table.define_vocabulary(
        tname=table_name,
        curie_template='%s:{RID}' % (ID_prefix),
        uri_template='/id/{RID}' if not URI_catalog_id else '/id/%s/{RID}' % (str(URI_catalog_id)), 
        column_defs=column_defs,
        key_defs=key_defs,
        fkey_defs=fkey_defs,
        comment=table_comment,
        provide_system=True
    )
    return table_def


# -- ===============================================================
# this section contains the helper functions for print model extras
#


FKEY_ACLS = {
    "default": { "insert": ["*"], "update": ["*"] },
    "RCBRMB": None,
}

# -----------------------------------------------------------
def set_ermrest_groups(catalog):
    # ermrest_groups["https://auth.globus.org/6068dc4b-73ee-4143-b606-29c6780f582f"] = 'rbkcc',
    global ermrest_groups
    resp = catalog.get("/attribute/public:ERMrest_Group/ID,Display_Name")
    rows = resp.json()
    for row in rows:
        ermrest_groups[row["ID"]] = row["Display_Name"]

    resp = catalog.get("/attribute/public:ERMrest_Client/ID,Display_Name,Email")
    rows = resp.json()
    for row in rows:
        ermrest_groups[row["ID"]] = row["Email"]

# ----------------------------------------------------------
# replace group id with group name based on the value stored in ermrest
def humanize_acls(acls):
    str = {}
    for role, groups in acls.items():
        hgroups = []
        for g in groups: 
            if g in ermrest_groups.keys():
                hgroups.append(ermrest_groups[g])
            else: 
                hgroups.append(g)
        str[role] = hgroups
    return str

# ----------------------------------------------------------
# replace group id with group name based on the value stored in ermrest
#
def humanize_acl_bindings(acl_bindings):
    #print("---%s---" % (acl_bindings))
    str = acl_bindings.copy()
    for name, acl_binding in str.items():
        if not acl_binding:
            continue
        scope_acl = []
        for g in acl_binding["scope_acl"]:
            if g in ermrest_groups.keys():
                scope_acl.append(ermrest_groups[g])
            else: 
                scope_acl.append(g)
        acl_binding["scope_acl"] = scope_acl
        #print("set acl_bindings [%s][%s] to %s" % (name, "scope_acl", scope_acl))
    return str

# ----------------------------------------------------------
'''
  print_table_model_extras prints annotations, acls, and acl_bindings
'''
def print_table_model_extras(model, schema_name, table_name, annotations=True, acls=True, acl_bindings=True, exclude_default_fkey=True):
    default_fkey_acls = {"insert": ["*"], "update": ["*"]}    
    table = model.schemas[schema_name].tables[table_name]
    
    if not ermrest_groups:
        set_ermrest_groups(model.catalog)        
    
    if annotations and table.annotations: print("  t-a   %s annotations: %s" % (table.name, json.dumps(table.annotations, indent=2)))
    if acls and table.acls: print("  t-acl %s: %s" % (table.name, humanize_acls(table.acls)))
    if acl_bindings and table.acl_bindings: print("  t-ab  %s: %s" % (table.name, humanize_acl_bindings(table.acl_bindings)))
    for cname in table.columns.elements:
        column = table.columns[cname]
        if annotations and column.annotations: print("    c-a %s.%s: %s" % (table.name, column.name, json.dumps(column.annotations, indent=2)))
        if acls and column.acls: print("    c-acl: %s.%s: %s" % (table.name, column.name, humanize_acls(column.acls)))
        if acl_bindings and column.acl_bindings: print("    c-ab  %s.%s: %s" % (table.name, column.name, humanize_acl_bindings(column.acl_bindings)))
    for key in table.keys:
        if annotations and key.annotations: print("    k-a    %s: %s" % (key.constraint_name, json.dumps(key.annotations, indent=2)))
    for fkey in table.foreign_keys:
        if annotations and fkey.annotations: print("    fk-a     %s: %s" % (fkey.constraint_name, json.dumps(fkey.annotations, indent=2)))
        if acls and fkey.acls:
            if (exclude_default_fkey and fkey.acls != default_fkey_acls) or (exclude_default_fkey == False):
                print("    fk-acl  %s: %s" % (fkey.constraint_name, humanize_acls(fkey.acls)))
        if acl_bindings and fkey.acl_bindings: print("    fk-ab   %s: %s" % (fkey.constraint_name, humanize_acl_bindings(fkey.acl_bindings)))


# ----------------------------------------------------------
'''
  print_schema_model_extras prints annotations, acls, and acl_bindings
'''
def print_schema_model_extras(model, schema_name, annotations=True, acls=True, acl_bindings=True, exclude_default_fkey=True):
    default_fkey_acls = {"insert": ["*"], "update": ["*"]}    
    schema = model.schemas[schema_name]

    if not ermrest_groups:
        set_ermrest_groups(model.catalog)        
    
    print("--------- %s ---------------" % (schema_name))
    if annotations and schema.annotations: print("s-a    s: %s: %s" % (schema_name, schema.annotations))
    if acls and schema.acls: print("s-acl  %s : %s" % (schema_name, humanize_acls(schema.acls)))
    for table in model.schemas[schema_name].tables.values():
        print_table_model_extras(model, schema_name, table.name, annotations=annotations, acls=acls, acl_bindings=acl_bindings, exclude_default_fkey=exclude_default_fkey)
    
# ----------------------------------------------------------            
def print_catalog_model_extras(model, annotations=True, acls=True, acl_bindings=True, exclude_default_fkey=True):
    if not ermrest_groups:
        set_ermrest_groups(model.catalog)        
    
    print("=========== catalog acls ============")
    if acls: print(humanize_acls(model.acls))
    for schema_name in model.schemas:
        print_schema_model_extras(model, schema_name, annotations=annotations, acls=acls, acl_bindings=acl_bindings, exclude_default_fkey=exclude_default_fkey)

 
# -----------------------------------------------------------
# throw an exception of CREATE or WRITE are in acls
def check_acl_types(acls, name):
    if not acls:
        return
    if "create" in acls.keys() or "write" in acls.keys(): 
        raise TypeError("ERROR: create/write are now allowed in acls: %s -> %s" % (name, humanize_acls(acls)))

# -----------------------------------------------------------    
def check_model_acl_types(model):
    if not ermrest_groups:
        set_ermrest_groups(model.catalog)        
    
    check_acl_types(model.acls, "catalog")    
    for schema_name in model.schemas:
        schema = model.schemas[schema_name]
        check_acl_types(schema.acls, schema_name)
        for table in schema.tables.values():
            check_acl_types(table.acls, "%s.%s" % (schema_name, table.name))
            for cname in table.columns.elements:
                column = table.columns[cname]
                check_acl_types(column.acls, "%s.%s.%s" % (schema_name, table.name, cname))
            for fkey in table.foreign_keys:
                check_acl_types(fkey.acls, "%s.%s.%s" % (schema_name, table.name, fkey.constraint_name))
    

# -----------------------------------------------------------
# clear all the ACLs in the table and reset the fkey.acls to default
def clear_table_acls(table):

    if False: # to debug
        for fkey in table.foreign_keys:
            from_cols = {c.name for c in fkey.column_map.keys()}
            to_cols = {c.name for c in fkey.column_map.values()}
            pk_table = fkey.pk_table
            print("       B-- fk %s:%s (%s->%s:%s) acls: %s, acl_bindings: %s" % (table.name, fkey.constraint_name, from_cols, fkey.pk_table.name, to_cols, fkey.acls, fkey.acl_bindings))
            
    table.clear(clear_comment=False, clear_annotations=False, clear_acls=True, clear_acl_bindings=True)

    if False: # to debug
        for fkey in table.foreign_keys:
            from_cols = {c.name for c in fkey.column_map.keys()}
            to_cols = {c.name for c in fkey.column_map.values()}
            pk_table = fkey.pk_table
            print("       C-- fk %s:%s (%s->%s:%s) acls: %s, acl_bindings: %s" % (table.name, fkey.constraint_name, from_cols, fkey.pk_table.name, to_cols, fkey.acls, fkey.acl_bindings))

    # assign default to fkey acls
    for fkey in table.foreign_keys:
        fkey.acls.clear()
        fkey.acls.update(FKEY_ACLS["default"])
        if False: # to debug
            from_cols = {c.name for c in fkey.column_map.keys()}
            to_cols = {c.name for c in fkey.column_map.values()}
            pk_table = fkey.pk_table        
            print("       S-- fk %s:%s (%s->%s:%s) acls: %s, acl_bindings: %s" % (table.name, fkey.constraint_name, from_cols, fkey.pk_table.name, to_cols, fkey.acls, fkey.acl_bindings))        

# -----------------------------------------------------------                
# clear all acls and acl_bindings under the schema
def clear_schema_acls(schema):
    # NOTE: There is a bug in the fkey clear. It doesn't set the fkey acls to default.
    # Uncomment and ignore the rest of the code when the bug is fixed
    #schema.clear(clear_comment=False, clear_annotations=False, clear_acls=True, clear_acl_bindings=True)
    
    schema.acls.clear()
    for table in schema.tables.values():
        clear_table_acls(table)

            
# =================================================================================
# helper functions to iternate over the model and return a set of tables, columns
# according to the specified parameters
#
# ------------------------------------------------------------------------------------------------    
def get_schemas(model, schema_pattern=None, schema_names=[]):
    schemas = set()
    for sname, schema in model.schemas.items():
        if schema_pattern and re.match(sname, schema_pattern):
            schemas.add(schema)
    for sname in schema_names:
        schemas.add(model.schemas[sname])
    return schemas

# ----------------------------
# error if schema doesn't exist.
# ignore tables that do not exist. 
def get_tables(model, schema_pattern=None, schema_names=[], table_pattern=None, table_names=[], exclude_schemas=[]):
    tables = set()
    sname_list = schema_names
    tname_list = table_names
    for sname, schema in model.schemas.items():
        if schema_pattern and re.search(schema_pattern, sname):        
            for tname, table in schema.tables.items():
                if table_pattern and re.search(table_pattern, tname):
                    tables.add(table)
                    #print("t: add %s.%s" % (sname, tname))
            for tname in tname_list:
                if tname in schema.tables.keys():
                    table = schemas.tables[tname]
                    tables.add(table)
                    #print("t: add %s.%s" % (sname, table.name))                        
                else:
                    # print("tname: %s.%s does not exist" % (sname, tname))
                    pass

    # assume schema exists
    for sname in sname_list:
        schema = model.schemas[sname]
        for tname, table in schema.tables.items():
            if table_pattern and re.search(table_pattern, tname):
                tables.add(table)
                #print("t: add %s.%s" % (table.schema.name, tname))                
        else:
            for tname in tname_list:
                if tname in schema.tables.keys():
                    table = schema.tables[tname]
                    tables.add(table)
                    #print("t: add %s.%s" % (sname, table.name))                    
                else:
                    # print("tname: %s.%s does not exist" % (sname, tname))
                    pass
    return tables

# ----------------------------    
def get_columns_helper(table, column_pattern, column_names=[], exclude_schemas=[], exclude_tables=[]):
    columns = set()
    # no need to set columns that are in schema or tables that are not in model
    if table.schema in exclude_schemas or table in exclude_tables:
        return columns
    for cname in table.columns.elements:
        column = table.columns[cname]
        if column_pattern and re.search(column_pattern, cname):
            columns.add(column)
    for cname in column_names:
        if cname in table.columns.elements:
            columns.add(table.columns[cname])
        else:
            #print("cname: %s.%s.%s does not exist" % (table.schema.name, table.name, cname))
            pass

    return columns
            
# ----------------------------    
def get_columns(model, schema_pattern=None, schema_names=[], table_pattern=None, table_names=[], column_pattern=None, column_names=[], exclude_schemas=[], exclude_tables=[]):
    columns = set()
    for sname, schema in model.schemas.items():
        if schema_pattern and re.search(schema_pattern, sname):
            for tname, table in schema.tables.items():
                if table_pattern and re.search(table_pattern, tname):
                    columns.update(get_columns_helper(table, column_pattern, column_names, exclude_schemas, exclude_tables))
            for tname in table_names:
                columns.update(get_columns_helper(schema.tables[tname], column_pattern, column_names, exclude_schemas, exclude_tables))

    for sname in schema_names:
        schema = model.schemas[sname]
        for tname, table in schema.tables.items():
            if table_pattern and re.search(table_pattern, tname):
                columns.update(get_columns_helper(table, column_pattern, column_names, exclude_schemas, exclude_tables))
        for tname in table_names:
            columns.update(get_columns_helper(schema.tables[tname], column_pattern, column_names, exclude_schemas, exclude_tables))

    return columns            

# -- ==========================================================================
# -- annotation related utility functions
# --
# 
def set_column_annotations(columns, tag, annotation):
    for column in columns:
        column.annotations[tag].update(annotation)

# -- ------------------------------------------------------------------------------------
def add_fkey_source_definitions(table, from_cname, to_tname, fkey_source_name):
    print("add_fkey_source_definitions: %s, %s, %s" % (from_cname, to_tname, fkey_source_name))
    if from_cname not in table.columns.elements: return
    source_fkey = None
    for fkey in table.foreign_keys:
        #from_cols = {c.name for c in fkey.column_map.keys()}
        #to_cols = {c.name for c in fkey.column_map.values()}
        #print(" - %s, %s " % (fkey.constraint_name, fkey.pk_table.name))
        if fkey.pk_table.name == to_tname:
            source_fkey = fkey
            break

    if not source_fkey: return
    
    fkey_source_def = {
        "source" : [ {"outbound": [table.schema.name, source_fkey.constraint_name]}, "RID" ],
        "markdown_name" : from_cname.replace("_", " ")
    }

    table.annotations.setdefault(
        tag["source_definitions"],
        {
            "columns": True,
            "fkeys": True,
        }        
    )
    table.source_definitions.setdefault(
        "sources",
        {}
    )[fkey_source_name] = fkey_source_def

    print(table.source_definitions)

# -- ------------------------------------------------------------------------------------
def print_schema_annotations(model, schema_name, tags):
    schema =  model.schemas[schema_name]
    if schema.annotations:
        print("def update_%s(model):" % (schema.name))
        print('    schema = model.schemas["%s"]' % (schema.name))
        print('    # ----------------------------')
        # check annotation keys
        for key, annotation in schema.annotations.items():
            if tags and key not in tags: continue
            if key not in tag2name.keys():
                print("ERROR: %s -> %s" % (key, json.dumps(annotation, indent=4)))
                continue
            print('    schema.%s.update(' % (table.name, tag2name[key]))            
            print('%s' % (json.dumps([schema.annotations], indent=4)))
            print(')\n')

    for table in schema.tables.values():
        #if "Curation_Status" in table.columns.elements: add_fkey_source_definitions(table, "Curation_Status", "Status", "curation_status_fkey")
        #if "Record_Status" in table.columns.elements: add_fkey_source_definitions(table, "Record_Status", "Record_Status", "record_status_fkey")
        if not table.annotations: continue
        print("def update_%s_%s(model):" % (schema.name, table.name))
        print('    schema = model.schemas["%s"]' % (schema.name))
        print('    table = schema.tables["%s"]' % (table.name))
        
        for key, annotation in table.annotations.items():
            if tags and key not in tags: continue            
            if key not in tag2name.keys():
                print("ERROR: %s -> %s" % (key, json.dumps(annotation, indent=4)))
                continue
            if key not in per_schema_annotation_tags: continue
            print('    # ----------------------------')
            print('    schema.tables["%s"].%s.update(' % (table.name, tag2name[key]))
            print('%s' % (json.dumps([annotation], indent=4)))
            print(')\n')
                
        for column in table.columns:
            if column.name in ["RID", "RCT", "RCB", "RMT", "RMB"]: continue            
            for key, annotation in column.annotations.items():
                if tags and key not in tags: continue                
                if key not in tag2name.keys():
                    print("ERROR: %s -> %s" % (key, json.dumps(annotation, indent=4)))
                    continue
                if key not in per_schema_annotation_tags: continue                
                print('    # ----------------------------')
                print('    schema.tables["%s"].columns["%s"].%s.update(' % (table.name, column.name, tag2name[key]))
                print('%s' % (json.dumps([annotation], indent=4)))
                print(')\n')

        for fkey in table.foreign_keys:
            if not fkey.annotations: continue
            for key, annotation in fkey.annotations.items():
                if tags and key not in tags: continue                
                if key not in tag2name.keys():
                    print("ERROR: %s -> %s" % (key, json.dumps(annotation, indent=4)))
                    continue
                if key not in per_schema_annotation_tags: continue
                print('    # ----------------------------')
                print('    schema.tables["%s"].foreign_keys[(schema,"%s")].%s.update(' % (table.name, fkey.constraint_name, tag2name[key]))
                print('%s' % (json.dumps([annotation], indent=4)))
                print(')\n')
            
        print()

    print("def update_%s_annotations(model):" % (schema.name))
    for table in schema.tables.values():
        if not table.annotations: continue
        print('    update_%s_%s(model)' % (schema.name, table.name))

                               
# -- ------------------------------------------------------------------------------------
# presence_annotations: tag["generated"], tag["immutable"], tag["non_deletable", tag["required"]
def print_presence_tag_annotations(model, presence_tags):
    presence_tag_set = set(presence_tags)
    annotated_dict = {}
    
    for schema in model.schemas.values():
        annotated_set = presence_tag_set.intersection(set(schema.annotations.keys()))
        if annotated_set:
            annotated_dict.setdefault((schema.name, None, None), annotated_set)
        for table in schema.tables.values():
            annotated_set = presence_tag_set.intersection(set(table.annotations.keys()))            
            if annotated_set: annotated_dict.setdefault((schema.name, table.name, None), annotated_set)
            for column in table.columns:
                #if column.name in ["RID", "RCT", "RMT", "RCB", "RMB", "Curation_Status", "Record_Status", "Record_Status_Detail"]: continue
                #if column.name in ["RID", "RCT", "RMT", "RCB", "RMB"]: continue
                annotated_set = presence_tag_set.intersection(set(column.annotations.keys()))            
                if annotated_set: annotated_dict.setdefault((schema.name, table.name, column.name), annotated_set)

    print("# ---- presence tags: %s -----" % (presence_tags))
    for key, annotated_set in annotated_dict.items():
        sname, tname, cname = key
        print("%s.%s.%s: %s" % (sname, tname, cname, {tag2name[t] for t in annotated_set}))

# -- ----------------------------------------------------------------------
# decreated: replace byy print_presence_tag_annotation(model, [tag["generated"]]
# TODO: delete
def print_generated_elements(model):
    generated_dict = {}
    for schema in model.schemas.values():
        if schema.generated: 
            generated_dict.setdefault((schema.name, None), set())
        for table in schema.tables.values():
            if table.generated:
                generated_dict.setdefault((schema.name, table.name), set())
                for column in table.columns:
                    #if column.name in ["RID", "RCT", "RMT", "RCB", "RMB", "Curation_Status", "Record_Status", "Record_Status_Detail"]: continue
                    if column.name in ["RID", "RCT", "RMT", "RCB", "RMB"]: continue                    
                    if column.generated:
                        generated_dict.setdefault((schema.name, table.name), set()).add(column.name)

    print("# ---- generated elements ----")
    for key, cnames in generated_dict.items():
        sname, tname = key
        print("generated %s:%s: %s" % (sname, tname, cnames))

# -- ----------------------------------------------------------------------
# decreated: replace byy print_presence_tag_annotation(model, [tag["required"]]
# TODO: delete
def print_required_annotations(model):
    required_dict = {}
    for schema in model.schemas.values():
        for table in schema.tables.values():
            for column in table.columns:
                if column.name in ["Principal_Investigator", "Consortium"]: continue
                if column.required:
                    required_dict.setdefault((schema.name, table.name), set()).add(column.name)

    print("# ---- required elements ----")
    for key, cnames in required_dict.items():
        sname, tname = key
        print("required %s:%s: %s" % (sname, tname, cnames))
        
# -- ------------------------------------------------------------------------
def print_isolated_tables(model):
    referenced_tables = set()
    referring_tables = set()
    for schema in model.schemas.values():
        for table in schema.tables.values():
            if table.foreign_keys:
                referring_tables.add(table)
            for fkey in table.foreign_keys:
                referenced_tables.add(fkey.pk_table)

    print("# ----- print isolated/outbound-only/inbound-only tables ---- ")
    for schema in model.schemas.values():
        for table in schema.tables.values():
            if table not in referenced_tables and table not in referring_tables:
                print("-- isolated: %s:%s" % (table.schema.name, table.name))
            if table in referenced_tables - referring_tables:
                print("-> in_only: %s:%s" % (table.schema.name, table.name))
            if table in referring_tables - referenced_tables:
                print("<- out_only: %s:%s" % (table.schema.name, table.name))
            
       
# ======================================================
# ---------------------------------------------------------------------------------------
# clear anntoations contained within a table
#
def clear_table_annotations(model, schema_name, table_name, clear_tags):
    '''
    On a specified table, clear table/column/fkey annotations that are specified in clear_tags.
    param:
      clear_tags: a set of annotation tags to clear
    '''
    table = model.schemas[schema_name].tables[table_name]
    t_tags = list(table.annotations.keys()).copy()
    for tt in t_tags:
        if tt in clear_tags : table.annotations.pop(tt, None)
        for column in table.columns:
            c_tags = list(column.annotations.keys()).copy()
            for t in c_tags:
                if t in clear_tags : column.annotations.pop(t, None)
        for fkey in table.foreign_keys:
            fk_tags = list(fkey.annotations.keys()).copy()
            for t in fk_tags:
                if t in clear_tags : fkey.annotations.pop(t, None)

# ---------------------------------------------------------------------------------------                
# NOTE: This function also remove tags that are not in the tag.values()
def clear_schema_annotations(model, schema_name, clear_tags):
    '''
    For all tables in a specified schema, clear table/column/fkey annotations that are specified in clear_tags.
    param:
      clear_tags: a set of annotation tags to clear
    '''   
    schema = model.schemas[schema_name]
    s_tags = list(schema.annotations.keys()).copy()
    for t in s_tags:
        if t in clear_tags : schema.annotations.pop(t, None)
    for table in schema.tables.values():
        clear_table_annotations(model, schema_name, table.name, clear_tags)

# ---------------------------------------------------------------------------------------        
def clear_catalog_annotations(model, clear_tags):
    '''
    Clear all annotations in the clear_tags for all model elements in the catalog.
    '''
    # clear catalog-level annotations
    for t in clear_tags:
        if t in model.annotations: model.annotations.pop(t, None)
    # clear the rest of annotations
    for schema in model.schemas.values():
        clear_schema_annotations(model, schema.name, clear_tags)

# ---------------------------------------------------------------------------------------        
def clear_all_schema_annotations(model, clear_tags):
    '''
    For all tables in all schemas, clear table/column/fkey annotations that are specified in clear_tags.
    param:
      clear_tags: a set of annotation tags to clear
    '''
    for schema in model.schemas.values():
        clear_schema_annotations(model, schema.name, clear_tags)

# ---------------------------------------------------------------------------------------        
def clear_catalog_specific_annotations(model, clear_tags):
    '''
    clear catalog-specific annotations
    '''
    for t in clear_tags:
        if t in model.annotations: model.annotations.pop(t, None)
        
# ---------------------------------------------------------------------------------------

# -- clear schema, table, columns with certain tags
# TODO: should add keys and fkeys for completeness
def clear_catalog_wide_annotations_legacy(model, clear_tags=catalog_wide_annotation_tags):
    for schema in model.schemas.values():
        s_tags = list(schema.annotations.keys()).copy()
        for tag in s_tags:
            if tag in clear_tags: schema.annotations.pop(tag, None)
        for table in schema.tables.values():
            t_tags = list(table.annotations.keys()).copy()
            for tag in t_tags:
                if tag in clear_tags: table.annotations.pop(tag, None)
            for column in table.columns:
                c_tags = list(column.annotations.keys()).copy()
                for tag in c_tags:
                    if tag in clear_tags: column.annotations.pop(tag, None)
        
# ======================================================        
