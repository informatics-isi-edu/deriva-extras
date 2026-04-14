import sys
import json
import os
import re
import binascii
import requests
from collections import namedtuple
from dataclasses import dataclass


from deriva.core import ErmrestCatalog, HatracStore, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, urlunquote, DerivaServer, get_credential, BaseCLI, format_exception, NotModified, DEFAULT_HEADERS, DEFAULT_CHUNK_SIZE, DEFAULT_MAX_CHUNK_LIMIT, DEFAULT_MAX_REQUEST_SIZE, Megabyte, get_transfer_summary, calculate_optimal_transfer_shape, DEFAULT_SESSION_CONFIG
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey
from deriva.utils.extras.shared import ConfigCLI, DCCTX
from deriva.utils.extras.model import create_table_if_not_exist, create_vocab_tdoc
from deriva.utils.extras.data import insert_if_not_exist

'''
  * See https://github.com/informatics-isi-edu/protein-database/wiki/JSON-schema-semantics on how to interpret mmcif json schema docs
    - $ref: Foreign keys
    - _primary_key: If true indicates that the data item is a primary key
    - type: Indicates the type of data (string, integer, number)
    - examples: Examples of the data item (shown while hovering on column name)
    - description: Description of the data item (shown while hovering on column name)
    - rcsb_description: Same as description; redundant
    - attribute_groups: Group together data items that form composite keys. The id and labels within the attribute groups differentiate the multiple instances of the composite foreign keys. These are used along with $ref.
    - enum: Controlled vocabulary of allowed values for a data item
    - rcsb_enum_annotated: Same as enum; redundant
    - required: List of mandatory data items in a table
   Note: Each table has a structure_id data item that points to the entry_id, which is the PDB accession code.
  * ENUM case sensitivity:
    - Some vocab tables are case sensitive, some aren't.
    - Use this code to determine: https://github.com/informatics-isi-edu/protein-database/blob/master/scripts/dictionary-api/testGetUcode.py
      - input: For MA, it is this one: https://raw.githubusercontent.com/ihmwg/ModelCIF/master/dist/mmcif_ma.dic (edited)
      - ucode is case insensitive. code is case sensitive.   
      - See the readme here: https://github.com/informatics-isi-edu/protein-database/tree/master/scripts/dictionary-api

'''

mmcif = None  # the mmcif definitions
#vocab_schema_name = "Vocab"
#ma_schema_name = "MA"
#vocab_values = {}

# ===================================================================================
# ===================================================================================

def dump_json_to_file(file_path, json_object):
    #print("dump_json_to_file: file_path %s" % (file_path))
    fw = open(file_path, 'w')
    json.dump(json_object, fw, indent=4)
    fw.write(f'\n')
    fw.close()

# ---------------------------------------------------------------------------
def get_ermrest_vocab_table_def(tname, tdef, cname):
    cdef = get_cdef(tdef, cname)    
    if "enum" not in cdef.keys(): return None
    vocab_tname = "%s_%s" % (tname, cname)
    vocab_tcomment = None
    vocab_tdoc = create_vocab_tdoc(vocab_schema_name, vocab_tname, vocab_tcomment, False)
    # add to global variables
    vocab_values[vocab_tname] = cdef["enum"]
    payload = []
    for term in cdef["enum"]:
        payload.append({"Name": term})
    # add to vocab_tables
    return (vocab_tdoc, payload)


# ==========================================================================
class mmCIFTable():
    """
    Current not used
    """
    def __init__(self, mmcif_schema, tname, tdef):
        self.table_name = tname
        self.mmcif_tdef = tdef
        self.ermrest_table = get_ermrest_table_def(tname, tdef)


class mmCIFErmrestModel():
    """Ermrest model-related definitions generated from mmCIF.
    This model is not automatically created.
    """
    identifier_limit = 65
    output_dir = "/tmp"
    structure_id_Structure_RID_name = "structure_denorm"
    mmcif = None
    domain_schema_name = "PDB"
    vocab_schema_name = "Vocab"
    ermrest_domain_schema = None
    ermrest_domain_tables = {}   
    ermrest_vocab_schema = None
    ermrest_vocab_tables = {}    # mapping of enum column to tdoc: { (tname, cname) -> ermrest_tdocs, .. }
    ermrest_vocab_keys = {}
    ermrest_vocab_fkeys = {}
    apply_common_vocab = True    # whether to consolidate common vocab tables
    vocab_native2common = {}
    mmcif_key_defs = {}
    mmcif_fkey_defs = {}    
    combo_rid_columns = set()
    combo_keys = {}
    
    # common tables in mmCIF
    combine_yesno = True         # whether to combine different forms of yes/no into one table
    if combine_yesno:
        # if need to combine YES/No further (future?)
        common_vocab_table_dict = {        
            ("YesNo_All", "Name"): ["n", "no", "y", "yes"],
            ("YesNo", "Name"): ["No", "Yes"],             # Place holder for Name
            ("YesNo", "Name_Short"): ["N", "Y"],
            ("YesNo", "Name_Upper"): ["NO", "YES"],
            ("YesNo", "Name_Lower"): ["no", "yes"],
            ("Cardinality", "Name"): ["ALL", "ANY"],
        }
    else:
        common_vocab_table_dict = {        
            ("YesNo_All", "Name"): ["n", "no", "y", "yes"],
            ("YesNo_Short", "Name"): ["N", "Y"],
            ("YesNo_Upper", "Name"): ["NO", "YES"],
            ("YesNo_Lower", "Name"): ["no", "yes"],
            ("Cardinality", "Name"): ["ALL", "ANY"],
        }
        
    common_vocab_tnames = set([tname for tname, cname in common_vocab_table_dict.keys()])
    enum_to_common_vocab_tname = {
        ','.join(sorted(enum)): (tname, cname)
        for (tname, cname), enum in common_vocab_table_dict.items()
    }
    vocab_common2native = {
        (tname, cname): []
        for (tname, cname) in common_vocab_table_dict.keys()
    }
    #print("enum_to_common_vocab_tname: %s" % (json.dumps(enum_to_common_vocab_tname, indent=4)))

     
    def __init__(self, mmcif_model_file, main_sname, vocab_sname, output_dir="/tmp"):
        self.domain_schema_name = main_sname
        self.vocab_schema_name = vocab_sname
        self.ermrest_vocab_tables.update(self.create_common_ermrest_vocab_tables())
        #print(json.dumps(list(self.ermrest_vocab_tables.values()), indent=4))
        
        with open(mmcif_model_file) as json_file:
            self.mmcif = json.load(json_file)
        json_file.close()

        # Extract key and fkey first before creating ermrest table. This is because extra keys (e.g. due to optional fkeys definitions)
        # might be created later while going through tables
        for tname, tdef in self.get_tdefs(self.mmcif).items():
            self.mmcif_key_defs[tname] = self.extract_mmcif_key_defs(tname, tdef, verbose=False)
        print("----------- First round key extractions are done! ----------------\n")            
        for tname, tdef in self.get_tdefs(self.mmcif).items():            
            self.mmcif_fkey_defs[tname] = self.extract_mmcif_fkey_defs(tname, tdef, verbose=True)
        print("----------- First round fkey extractions are done! ----------------\n")

        # create ermrest table definitions
        for tname, tdef in self.get_tdefs(self.mmcif).items():
            if True or tname in ["pdbx_audit_revision_history", "entry", "pdbx_entry_details", "chem_comp", "entity_poly_seq"]:
                self.ermrest_domain_tables[tname] = self.get_ermrest_table_def(tname, tdef)
                self.ermrest_vocab_tables.update(self.get_ermrest_vocab_table_defs(tname, tdef))

        #Add extra columns and key to key defs e.g. RID columns
        print("INIT: Adding RID columns - total: %d" % (len(self.combo_rid_columns)))
        for (tname, cname, is_optional, ref_tname) in sorted(self.combo_rid_columns):
            print("INIT: Adding RID column: %s %s %s -> %s" % (tname, cname, is_optional, ref_tname))
            self.ermrest_domain_tables[tname]["column_definitions"].append(Column.define(cname, builtin_types["text"], nullok=is_optional))

        # already added. no need to add
        print("INIT: Adding combo keys - total: %d" % (len(self.combo_keys)))        
        for (tname, kname, suffix), cnames in self.combo_keys.items():
            print("INIT: Adding combo key: %s %s %s => %s" % (tname, kname, suffix, cnames))
            #self.ermrest_domain_tables[tname]["keys"].append(
            #    Key.define(cnames, constraint_names=[[ self.domain_schema_name, "%s_%s_%s" % (tname, kname, suffix) ]] )
            #)


        #print("\n\n --- ermrest_domain_tables [%d] dump: %s" % (len(self.ermrest_domain_tables), json.dumps(list(self.ermrest_domain_tables.keys()), indent=4)))
        #print("\n\n --- vocab tables [%d] dump: %s " % (len(self.ermrest_vocab_tables), self.ermrest_vocab_tables.keys()))
        #print("\n\n --- vocab_native2common [%d] dump: %s" % (len(self.vocab_native2common), self.vocab_native2common))
        #print("\n\n --- vocab_common2native [%d] dump: %s" % (len(self.vocab_common2native), json.dumps(self.vocab_common2native, indent=4)))
        #self.print_common_vocab_fkeys()
        
        self.print_common_enums()
        
        self.ermrest_domain_schema = self.get_ermrest_schema_def(self.domain_schema_name, list(self.ermrest_domain_tables.values()))
        self.ermrest_vocab_schema =  self.get_ermrest_schema_def(self.vocab_schema_name, list(self.ermrest_vocab_tables.values()))

        #dump_json_to_file(f"{output_dir}/ermrest_tables.json", self.ermrest_domain_schema)
        #dump_json_to_file(f"{output_dir}/vocab_tables.json", self.ermrest_vocab_schema)
        

    @classmethod
    def load_mmcif(cls, mmcif_model_file):
        with open(mmcif_model_file) as json_file:
            mmcif = json.load(json_file)
        json_file.close()
        return  mmcif
        
    @classmethod        
    def create_common_ermrest_vocab_tables(cls):
        vocab_tdocs = {}
        tname2cnames = {}
        for tname, cname in cls.common_vocab_table_dict.keys():
            cnames = tname2cnames.setdefault(tname, [])
            # only add if cname is not Name
            if cname != "Name": cnames.append(cname)
        for tname, cnames in tname2cnames.items():
            print("tname: %s" % (tname))
            tdoc = create_vocab_tdoc(cls.vocab_schema_name, tname, None, False, other_cnames=tname2cnames[tname])            
            vocab_tdocs[(tname, None)] = tdoc
            if not cnames: continue
            for cdef in tdoc["column_definitions"]:
                if cdef["name"] in cnames: cdef["nullok"] = False
            for cname in cnames:
                tdoc["keys"].append(Key.define([cname], constraint_names=[[cls.vocab_schema_name, tname + "_" + cname + "_key"]]))
        return vocab_tdocs
    

    @classmethod
    def search_for_common_vocab_table(cls, enum):
        result = (None, None)
        if len(enum) > 4: return result
        enum_str = ','.join(sorted([str(i) for i in enum]))
        #print("-- enum: %s -> %s == %s" % (enum, enum_str, cls.enum_to_common_vocab_tname.keys()))
        if enum_str in cls.enum_to_common_vocab_tname.keys():
            #print("search_for_common_vocab_table: FOUND %s" % (cls.enum_to_common_vocab_tname[enum_str]))
            return cls.enum_to_common_vocab_tname[enum_str]
        else:
            return result
        
        
    def print_common_vocab_fkeys(self):
        print("--- Printing common vocab fkeys")
        for tdoc in self.ermrest_domain_tables.values():
            for fkey in tdoc["foreign_keys"]:
                if fkey["referenced_columns"][0]["table_name"] in self.common_vocab_table_dict.keys():
                    print("table: %s fkey to common_vocab: %s" % (tdoc["table_name"], json.dumps(fkey, indent=4)))
        
    def print_common_enums(self):
        enum_dicts={}
        for (tname, cname), ermrest_tdef in self.ermrest_vocab_tables.items():
            if cname is None: continue
            cdef=self.get_cdef(self.get_tdef(self.mmcif, tname), cname)
            enum = ",".join([ str(v) for v in cdef["enum"] ])
            #print("\n vocab key: %s:%s : %s" % (tname, cname, enum))
            #print(json.dumps(ermrest_tdef, indent=4))
            
            if enum not in enum_dicts.keys():
                enum_dicts[enum] = [(tname, cname)]
            else:
                enum_dicts[enum].append((tname, cname))
                
        for k,v in enum_dicts.items():
            if len(v) > 2:
                print("k:%s [%d], v:%s" % (k, len(v), v))
        
    # ===================================================================================
    # mmCIF json doc helper functions
    #

    @classmethod
    def mmcif_to_ermrest_type(cls, mmcif_type):
        """
        Lookup corresponding ermrest column type based on mmcif type 
        """
        ermrest_type = {
            'string': 'text',
            'integer': 'int4',
            'number': 'float4'
        }
        return ermrest_type[mmcif_type]

    @classmethod
    def get_tdefs(cls, mmcif_dict):
        """
        Return table definitions in the mmcif_dict
        """
        return mmcif_dict["properties"]
    
    @classmethod
    def get_tdef(cls, mmcif_dict, tname):
        """
        Get table definition from mmcif model doc
        Parameters:
           - mmcif_dict: mmcif model (json)
           - tname: table name to extract the definition for
        """
        if tname not in  mmcif_dict["properties"].keys():
            #print("get_tdef ERROR: tname:%s - %s" % (tname, mmcif["properties"].keys()))
            raise Exception("ERROR: Unknown table name %s" % (tname))
        return mmcif_dict["properties"][tname]

    @classmethod    
    def get_cdefs(cls, tdef):
        """
        Get column definitions from mmcif table definition
        """        
        #print("tdef[type] = %s" % (tdef["type"]))
        if tdef["type"] == "object":
            cdefs = tdef["properties"]
        elif tdef["type"] == "array":
            cdefs = tdef["items"]["properties"]
        else:
            raise Exception("ERROR: Unknown mmCIF table type")
        #print(json.dumps(cdefs, indent=4))
        return cdefs

    @classmethod
    def get_cdef(cls, tdef, cname):
        """
        Get a specific column definition from mmcif table definition
        """                
        cdefs = cls.get_cdefs(tdef)
        return cdefs[cname]

    @classmethod
    def is_null_ok_column(cls, tname, tdef, cname):
        """
        Check whether the mmcif column is null_ok
        """
        required = None
        column_mapping = {
            "Structure_RID": "structure_id",
            "Entry_RID": "entry_id"
        }
        
        if tdef["type"] == "object":
            required = tdef["required"]
        elif tdef["type"] == "array":
            required = tdef["items"]["required"]

        if cname == "RID" and tname == "entry":
            null_ok = False
        elif cname in column_mapping.keys():
            null_ok = False if column_mapping[cname] in required else True
        else:
            null_ok = False if cname in required else True

        #if (tname == "ihm_cross_link_pseudo_site"):
        #    print("NULL_OK: tname:%s cname:%s %s" % (tname, cname, null_ok))

        return null_ok

    # ---------------------------------------------------------------------------
    @classmethod    
    def are_all_required_columns(cls, tname, tdef, cnames, exclude_cnames=[]):
        """
        True implies all columns are null_ok
        """
        #print("tname: %s tdev: %s" % (tname, json.dumps(tdef, indent=4)))
        required = True
        for cname in cnames:
            if cname in exclude_cnames: continue
            if cls.is_null_ok_column(tname, tdef, cname):
                required = False
                break
        if "symbol" in cnames:
            print("  -KEY: are_all_null_ok_columns: %s : %s -> %s" % (tname, cnames, required))
        return required

    @classmethod    
    def are_all_optional_columns(cls, tname, tdef, cnames, exclude_cnames=[]):
        """
        True implies all columns are null_ok
        """
        #print("tname: %s tdev: %s" % (tname, json.dumps(tdef, indent=4)))
        check_cnames = set(cnames) - set(exclude_cnames)
        if not check_cnames:
            return False
        
        optional = True
        for cname in check_cnames:
            if not cls.is_null_ok_column(tname, tdef, cname):
                optional = False
                break

        if (tname == "ihm_cross_link_pseudo_site"):
            print("NULL_OK: %s. tname:%s %s" % (optional, tname, [ "%s:%s" % (c, cls.is_null_ok_column(tname, tdef, c)) for c in cnames] ))
            
        return optional
    
    # ---------------------------------------------------------------------------
    # 
    # TODO: fix mmcif reference
    @classmethod
    def get_reference_cdef(cls, mmcif_dict, tname, tdef, cname):
        """
        Traverse through sequences of $ref to retrieve the native column.
           Return (referenced table name, referenced column name, referenced column definition)
        """                
        cdef = cls.get_cdef(tdef, cname)
        if "$ref" not in cdef.keys():
            raise Exception("ERROR: cname %s is not a reference column" % (cname))
        #print("** get_reference_cdef %s:%s -> %s" % (tname, cname, cdef["$ref"]))
        is_native=False
        while is_native is not True:
            (ref_tname, ref_cname) = cdef["$ref"][1:].split("/")
            ref_tdef = cls.get_tdef(mmcif_dict, ref_tname)
            ref_cdef = cls.get_cdef(ref_tdef, ref_cname)
            #print(" - get_reference_cdef: %s %s -> %s" % (ref_tname, ref_cname, ref_cdef["$ref"] if "$ref" in ref_cdef.keys() else "Done"))
            if "type" in ref_cdef.keys():
                is_native=True
                #print(" - Found a match: %s:%s:%s" % (ref_tname, ref_cname, ref_cdef["type"]))
                return (ref_tname, ref_cname, ref_cdef)
            elif "$ref" in ref_cdef.keys():
                cdef = ref_cdef
            else:
                raise Exception("ERROR: Unknown cdef: %s -> %s" % (ref_cname, ref_cdef))
        

    # ===================================================================================
    def get_ermrest_schema_def(self, schema_name, table_defs, comment=None):
        """
        Create ermrest schema document that can be used for model creation in bulk
        """
        schema_def = Schema.define(schema_name, comment=comment)
        schema_def["tables"] = { t["table_name"] : t for t in table_defs }
        
        return schema_def

    # ---------------------------------------------------------------------------    
    # mmcif table properties: {'uniqueItems', 'type', 'rcsb_nested_indexing', 'additionalProperties', 'minItems', 'required', 'items', 'properties'}
    # mmcif array table items properties: {'properties', 'type', 'required', 'additionalProperties'}
    def get_ermrest_table_def(self, tname, tdef):
        """
        Return the corresponding ermrest table definition based on the mmCIF table definition.
           Parameters:
             - table name
             - mmcif table dict
           Notes:
             - For entry table, structure_id is removed from column definition to avoid confusion
             - Add "Stucture_RID" to the column list
        """
        ermrest_cnames = []        
        ermrest_cdefs = []
        ermrest_kdefs = []    
        ermrest_fkey_defs=[]
        vocab_ermrest_tdefs = {}
        cdefs = self.get_cdefs(tdef)


        for cname, cdef in cdefs.items():
            # -- Remove structure_id from the entry table e.g. id and structure_id are duplicate.
            if tname == "entry" and cname == "structure_id": continue
            # -- Remove structure_id if entry_id exists. entry_id is from mmCIF. structure_id is artificially added for the JSON schema.
            if cname == "structure_id" and "entry_id" in cdefs.keys():
                print("COLUMN_DEFS: Remove structure_id (entry_id already exists). tname: %s " % (tname))
                continue
            ermrest_cnames.append(cname)
            ermrest_cdefs.append(self.get_ermrest_column_def(self.mmcif, tname, tdef, cname))

        ermrest_kdefs.extend(self.get_ermrest_key_defs(tname, tdef, verbose=False))
        ermrest_kdefs.append(Key.define(["RID"], constraint_names=[[ self.domain_schema_name, "%s_RID_key" % (tname) ]] ))
        ermrest_fkey_defs.extend(self.get_ermrest_fkey_defs(tname, tdef, verbose=False))
        ermrest_fkey_defs.extend(self.get_ermrest_vocab_fkey_defs(tname, tdef, verbose=False))

        """
        # Note: no longer needed to add Structure_RID/Entry_RID column. Cause problems with chaise
        #
        # Extend base model for multi-entry DB and data integrity constraint
        # -- Add "Structure_RID" along side structure_id --> to ensure that structure_id cannot be change during chaise event
        
        if "entry_id" in ermrest_cnames:
            ermrest_cdefs.append(Column.define(
                "Entry_RID", 
                builtin_types["text"],
                nullok=self.is_null_ok_column(tname, tdef, "entry_id"),
            ))
        elif "structure_id" in ermrest_cnames and tname != "entry":
            ermrest_cdefs.append(Column.define(
                "Structure_RID", 
                builtin_types["text"],
                nullok=self.is_null_ok_column(tname, tdef, "structure_id"),
            ))
        else:
            if tname != "entry":
                raise Exception("COLUMN_DEF ERROR: Missing entry_id or structure_id: table %s" % (tname))
        """
        
        #    print("\nermrest_cdefs: %s" % (json.dumps(ermrest_cdefs, indent=4)))
        #    print("\nermrest_kdef: %s" % (json.dumps(ermrest_kdefs, indent=4)))
        #    print("\nermrest_fkey_defs: %s" % (json.dumps(ermrest_fkey_defs, indent=4)))
    
        table_def = Table.define(
            tname=tname,
            column_defs=ermrest_cdefs,
            key_defs=ermrest_kdefs,
            fkey_defs=ermrest_fkey_defs,
            comment=None,
            provide_system=True,
        )

        return table_def

    # ---------------------------------------------------------------------------
    #{'rcsb_description', 'type', '_attribute_groups', '$ref', 'minimum', 'maximum', 'rcsb_units', 'description', '_primary_key', 'format', 'rcsb_enum_annotated', 'enum', 'examples'}
    # tdef["required"]: contains a list of required field
    # rcsb_description contains context-based description. Most of them contains similar content as description.
    @classmethod
    def get_ermrest_column_def(cls, mmcif_dict, tname, tdef, cname):
        """
        Create ermrest column definition based on mmCIF model
        """

        cdef = cls.get_cdef(tdef, cname)
        keys = cdef.keys()
    
        # -- To handle reference case
        if "type" in cdef.keys():
            ctype = cls.mmcif_to_ermrest_type(cdef["type"])
        elif "$ref" in cdef.keys():
            ref_tname, ref_cname, ref_cdef = cls.get_reference_cdef(mmcif_dict, tname, tdef, cname)
            ctype = cls.mmcif_to_ermrest_type(ref_cdef["type"])
        else:
            raise Exception("ERROR: Expect either $ref or native column: cname:%s cdef: %s" % (cname, json.dumps(cdef, indent=4)))

        # Combine description and examples into the comment.
        comment=cdef["description"] if "description" in keys else None
        if "examples" in keys:
            examples = ", ".join(cdef["examples"])
            comment = "%s Examples: %s" % (comment, examples) if comment else "Examples: %s" % (examples)
            
        column_def = Column.define(
            cname,
            builtin_types[ctype],
            nullok=cls.is_null_ok_column(tname, tdef, cname),
            comment=comment,
        )
        return column_def
    
    
    # ---------------------------------------------------------------------------
    #  TODO: Key.define(["RID"], constraint_names=[[schema_name, table_name + "_RID_key"]]

    def is_composite_fkey(self, tname, tdef, attr_id, cnames):
        """
        Check whether a set of columns is a composite foreign key
           - It is a composite fkey if all its members are referencing the same table e.g. if
           a member is native type or a member refering to a different table, then it is a composite
           key instead of a composite fkey.
           - If multiple columns refer to the same refering column (e.g. [entry_id, structure_id]), this is not a proper composite fkeys 
        """
        cdefs = self.get_cdefs(tdef)        
        is_fkey = True
        ref_tnames = set()
        ref_cnames = set()
        for cname in cnames:
            cdef = cdefs[cname]
            if "$ref" not in cdef.keys():
                is_fkey = False
                break # this is key
            (ref_tname, ref_cname) = cdef["$ref"][1:].split("/")
            ref_tnames.add(ref_tname)
            ref_cnames.add(ref_cname)
            
        if not (len(ref_tnames) == 1 and len(ref_cnames) == len(cnames)):
            is_fkey = False

        """
        if is_fkey:
            print("IS_COMPOSITE_FKEY: IS FKEY. tname:%s key: %s -> %s ==> %s -> %s" % (tname, attr_id, cnames, ref_tnames, ref_cnames))
            pass
        """
        return is_fkey

    # ---------------------------------------------------------------------------        
    def is_composite_key(self, tname, tdef, attr_id, cnames):
        """
        Check whether the column list is a composite key
        """
        cdefs = self.get_cdefs(tdef)                
        is_primary_key = True
        # all primary and required
        for cname in cnames:
            if "_primary_key" not in cdefs[cname].keys() or cdefs[cname]["_primary_key"] != True:
                is_primary_key = False
        if is_primary_key:
            return True
        else:
            return not self.is_composite_fkey(tname, tdef, attr_id, cnames)
        
    
    # ---------------------------------------------------------------------------
    # TODO: Fix logic
    """
    tname_mapping = {
    # vocab specific
    "customized_fragment_library_flag": "fragment_library_flag",            
    # pdb specific
    "ihm_2dem_class_average_restraint": "2dem_cls_avg_restraint",
    "ihm_2dem_class_average_fitting": "2dem_cls_avg_fitting",            
    "ihm_geometric_object_list" : "geo_obj_list",
    "ihm_geometric_object_axis" : "geo_obj_axis",                        
    "ihm_geometric_object_transformation": "geo_obj_transformation",
    "ihm_geometric_object_distance_restraint": "geo_obj_distance_restraint",
    "ihm_geometric_object_plane": "geo_obj_plane", 
    "ihm_chemical_component": "chem_comp",
    "ihm_multi_state_scheme_connectivity": "mss_connectivity",
    # ma specific
    "ma_poly_template_library": "poly_temp_lib",
    }
    """
    def shorten_constraint_name(self, tname, orig_attr_name, suffix="fkey"):
        """
        There is a postgres limit to the key/fkey name. Make sure that the constraint names are within the limit.
        This function contains substitution rules to shortern the names. 
        """
        max_limit = self.identifier_limit
        orig_tname = tname
        attr_name = orig_attr_name
        constraint_name = "%s_%s_%s" % (tname, attr_name, suffix)
        if len(constraint_name) <= max_limit: return constraint_name

        mappings = {
            # ma specific
            "ma_poly_template_library": "ma_poly_temp_lib",
            # pdb specific
            "ihm_2dem_class_average": "2dem_cls_avg",
            "ihm_geometric_object" : "geo_obj",
            "ihm_chemical_component": "chem_comp",
            "multi_state_scheme": "mss",
            "template_sequence_identity_denominator": "temp_seq_iden_denominator",
            # vocab specific
            "customized_fragment_library_flag": "customized_fragment_lib_flag",            
        }
        # apply the same abbreviation to both table name and constraint name. 
        for k,v in mappings.items():
            if len(constraint_name) <= max_limit: break
            update = False
            if k in tname:
                tname = tname.replace(k,v)
                update = True
            if k in attr_name:
                attr_name = attr_name.replace(k,v)
                update = True
            if update:
                constraint_name = "%s_%s_%s" % (tname, attr_name, suffix)
                #print("SHORTEN_NAME: tname: %s (-> %s),  attr_name: %s (-> %s)  --> cname: %s [%d]" % (orig_tname, tname, orig_attr_name, attr_name, constraint_name, len(constraint_name)))

        if len(constraint_name) <= max_limit:
            print("SHORTEN_NAME: tname: %s,  attr_name: %s  ====> returns constraint name: %s [%d]" % (orig_tname,  orig_attr_name, constraint_name, len(constraint_name)))            
            return constraint_name
        else:
            raise Exception("STOP HERE: tname: %s, ctname: %s [%d]" % (tname, constraint_name, len(constraint_name))        )
        
    # ---------------------------------------------------------------------------
    def extract_mmcif_key_defs(self, tname, tdef, verbose=True):
        """
        Extract key definitions and adjust them appropriately. 
        """
        cdefs = self.get_cdefs(tdef)
        raw_key_defs = {}
        key_defs = {}
        primary_columns = []
        attr_id2cnames = {}
        default_primary_key_name = "primary"  # use this when number of columns > 2

        # -- read from the mmcif model and identify groups of columns for composite keys
        if verbose: print()
        for cname, cdef in cdefs.items():
            cdef_keys = cdef.keys()
            if "_primary_key" in cdef_keys:
                # TODO: better address structure_id and entry_id case
                if tname != "entry" and cname == "structure_id" and "entry_id" in cdefs.keys(): continue               
                primary_columns.append(cname)
            if "_attribute_groups" in cdef_keys:
                for group in cdef["_attribute_groups"]:
                    if "label" in group.keys(): continue
                    id = group["id"]
                    attr_id2cnames.setdefault(id, []).append(cname)
                    if cname == "structure_id" and "entry_id" in cdefs.keys():
                        raise EXCEPTION("STRUCTURE_ID_ERROR: structure_id participate in key defs when entry_id exist. tname: %s" % (tname))

        # -- create raw keys
        # -- _primary_key marked individual keys in the entry_table, otherwise, they are composite primary keys
        if tname == "entry":
            raw_key_defs[("primary", "key")] = ["id"]
        else:
            # key_name: participating column name or "primary". Due to length issue, use "primary"
            #primary_name = "_".join(primary_columns) if len(primary_columns) <= 2 else default_primary_key_name
            primary_name = default_primary_key_name
            raw_key_defs[(primary_name, "key")] = primary_columns

        # if all columns are $ref to the same table, then it is an fkey, not necessary a key?
        for attr_id, cnames in attr_id2cnames.items():
            if self.is_composite_key(tname, tdef, attr_id, cnames):
                if verbose: print("oo KEY: COMPOSITE: tname:%s  key: %s (%s) -> %s" % (tname, attr_id, "key", cnames))                
                if (attr_id, "key") in raw_key_defs.keys():
                    if verbose: print("  -KEY-DEF ERROR: DUPLICATE KEYS: IGNORE. tname: %s key: %s (%s) -> %s already exist" % (tname, attr_id, "key", cnames))
                else:
                    raw_key_defs[(attr_id, "key")] = cnames
            else:
                print("  -WARNING: KEY-DEF ERROR: NOT KEY: this is not a key! tname:%s kname: %s -> %s" % (tname, attr_id, cnames))
                pass

        # -- augment mmcif keys with additional deriva keys.
        # Add RID to all natural key
        # key suffix: natural key + structure_id/entry_id
        # key1 suffix: natural key + RID
        # key2 suffix: nature key + RID - structure_id --> only when it is needed
        for (attr_id, suffix), cnames in raw_key_defs.items():
            constraint_name = "%s_%s_%s" % (tname, attr_id, suffix)
            if tname == "entry":
                key_defs[(attr_id, suffix)] = cnames                
                #key_defs[("denorm", "key")] = ["id", "RID"]  # skip denorm
                if verbose: print("  -KEY ENTRY_TABLE: key_defs: %s" % (key_defs))
                break
            elif "entry_id" in cnames and "structure_id" in cnames:
                raise Exception("KEY_DEF ERROR: entry_id and structure_id in key list")
                new_cnames = cnames.copy()            
                if "structure_id" in cnames:
                    raise Exception("KEY_DEF ERROR: entry_id and structure_id are in key def")
                    new_cnames.remove("structure_id")  # remove structure_id if entry_id exists
                key_defs[(attr_id, suffix)] = new_cnames   # natural key             
            elif "entry_id" in cnames and len(cnames) == 1:   # entry_id instead of structure_id: no thing
                key_defs[(attr_id, suffix)] = cnames                                
                #key_defs[("entry_denorm", "key")] = ["entry_id", "Entry_RID"]
                if verbose: print("  **3e -KEY-DEF: ENTRY_ID entry_id is key. Create denorm key. tname: %s key: %s -> %s ==> using %s + entry_denorm[entry_id, Entry_RID]" % (tname, attr_id, cnames, cnames + ["Entry_RID"]))
            elif "structure_id" in cnames and len(cnames) == 1:
                key_defs[(attr_id, suffix)] = cnames                
                #key_defs[("structure_denorm", "key")] = ["structure_id", "Entry_RID"]
                if verbose: print("  **3 -KEY-DEF: STRUCTURE_ID structure_id is key. Create denorm key. tname: %s key: %s -> %s ==> using %s + entry_denorm[entry_id, Entry_RID]" % (tname, attr_id, cnames, cnames + ["Structure_RID"]))
            elif "entry_id" in cnames or "structure_id" in cnames: 
                key_defs[(attr_id, suffix)] = cnames
                if verbose: print("  **0 -KEY-DEF: NATURAL KEY: tname: %s, attr_id: %s (%s) -> %s " % (tname, attr_id, suffix, cnames))
            elif "structure_id" not in cnames and "entry_id" not in cnames:
                # Missing keys are those involved with matrix and vectors, and the following
                # entity_poly_seq key: entity_poly_seq_mm_poly_res_label_key -> ['entity_id', 'mon_id', 'num'].
                if verbose: print("  **1 -KEY-DEF: ABSENT_STRUCTURE_ID tname: %s key: %s -> %s. Will add structure_id." % (tname, constraint_name, cnames))
                if "entry_id" in cdefs.keys():
                    new_cnames = ["entry_id"] + cnames
                elif "structure_id" in cdefs.keys():
                    new_cnames = ["structure_id"] + cnames                    
                else:
                    raise Exception("KEY_DEF ERROR: Require either entry_id or structure_id in the table def")
                # TODO: this shouldn't be added
                #if ["structure_id", "Structure_RID"] not in key_defs.values():
                #    key_defs[("structure_denorm", "key")] = ["structure_id", "Structure_RID"]
                #    print("      + -KEY-DEF: ABSENT_STRUCTURE_ID - ADD structure_denorm tname: %s key: %s -> %s" % (tname, constraint_name, new_cnames))
                if set(new_cnames) not in [set(v) for v in raw_key_defs.values()]:
                    key_defs[(attr_id, suffix)] = new_cnames
                    if verbose: print("      + -KEY-DEF: ABSENT_STRUCTURE_ID - ADD STRUCTURE_ID KEYS: tname: %s key: %s -> %s" % (tname, constraint_name, new_cnames))
                else:
                    if verbose: print("      - -KEY-DEF: ABSENT_STRUCTURE_ID - DUPLICATE KEYS: tname: %s key with structure_id: %s already exist. [%s]" % (tname, new_cnames, raw_key_defs.values()))
                    pass
            else:
                raise Exception("KEY ERROR: UNKNOWN_KEY_DEF tname: %s, attr_id: %s (%s) -> %s " % (tname, attr_id, suffix, cnames))

        
        return key_defs

    # ---------------------------------------------------------------------------    
    def get_ermrest_key_defs(self, tname, tdef, verbose=True):
        '''
        Extract Ermrest keys from mmCIF table definition.
        "_attribute_groups" marks composite keys and fkeys
        "label" distinguish multiple fkeys to the same table.
        '''
        cdefs = self.get_cdefs(tdef)
        key_defs = self.mmcif_key_defs[tname] if tname in self.mmcif_key_defs.keys() else self.extract_mmcif_key_defs(tname, tdef)
        ermrest_key_defs = []
        
        if verbose: print("---- -eKEYS: tname: %s  keys[%d] : " % (tname, len(key_defs.keys())))
        # address constraint names
        for (kname, suffix), cnames in key_defs.items():
            constraint_name = "%s_%s_%s" % (tname, kname, suffix)                               
            is_required = self.are_all_required_columns(tname, tdef, cnames)
            if (len(cnames) > 1):
                if verbose: print("  x COMPOSITE -KEY [required=%s]:  %s [%d] ==> %s " % (is_required, constraint_name, len(cnames), cnames))
                pass
            else:
                if verbose: print("  x SINGLE -KEY [required=%s]:  %s [%d] ==> %s " % (is_required, constraint_name, len(cnames), cnames))
                pass
            if len(constraint_name) > self.identifier_limit:
                orig_constraint_name = constraint_name
                constraint_name = self.shorten_constraint_name(tname, constraint_name, cnames)
                print("    **3 -KEY ERROR: LENGTH_ERROR: key name %s [%d] is too long. -> Suggest: %s [%d]" % (orig_constraint_name, len(orig_constraint_name), constraint_name, len(constraint_name)))
            ermrest_key_defs.append(Key.define(cnames, constraint_names=[[self.domain_schema_name, constraint_name]]))
            # TODO: for all composite keys with structure_id, replace structure_id with RID for optional fkey

            
        return ermrest_key_defs

    # ---------------------------------------------------------------------------
    # HELP: This doesn' get called
    # TODO: TO DELETE
    def get_ermrest_vocab_fkey_defs_duplicate(self, tname, tdef, verbose=True):
        """
        Create ermrest fkey definitions of enum (which get turned into vocab table)
        """
        cdefs = self.get_cdefs(tdef)
        vocab_cname2tnames = {}
        ermrest_fkey_defs = []

        raise Exception("STOP HERE: this get called line 799")
        for cname, cdef in cdefs.items():
            if "enum" in cdef_keys:
                # check for common_vocab_tables
                ref_tname = self.search_for_common_vocab_table(cdef["enum"])
                if ref_tname and self.apply_common_vocab:
                    self.vocab_native2common[(tname, cname)] = ref_tname
                    self.vocab_common2native[ref_tname].append((tname, cname))
                else:
                    ref_tname = "%s_%s" % (tname, cname)
                vocab_cname2tnames[cname] = ref_tname

        for cname, ref_tname in vocab_cname2tnames.items():
            ermrest_fkey_defs.append(
                ForeignKey.define([cname], self.vocab_schema_name, ref_tname, ["Name"],
                                  constraint_names=[[self.vocab_schema_name, tname + "_%s_fkey" % (cname)]],
                                  on_update="CASCADE",
                                  on_delete="SET NULL"   
                                  ),
            )
            

    # ---------------------------------------------------------------------------
    """
# -- not fkeys
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_2dem_class_average_fitting kname: matrix -> ['rot_matrix[1][1]', 'rot_matrix[1][2]', 'rot_matrix[1][3]', 'rot_matrix[2][1]', 'rot_matrix[2][2]', 'rot_matrix[2][3]', 'rot_matrix[3][1]', 'rot_matrix[3][2]', 'rot_matrix[3][3]']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_2dem_class_average_fitting kname: vector -> ['tr_vector[1]', 'tr_vector[2]', 'tr_vector[3]']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_data_transformation kname: matrix -> ['rot_matrix[1][1]', 'rot_matrix[1][2]', 'rot_matrix[1][3]', 'rot_matrix[2][1]', 'rot_matrix[2][2]', 'rot_matrix[2][3]', 'rot_matrix[3][1]', 'rot_matrix[3][2]', 'rot_matrix[3][3]']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_data_transformation kname: vector -> ['tr_vector[1]', 'tr_vector[2]', 'tr_vector[3]']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_geometric_object_transformation kname: matrix -> ['rot_matrix[1][1]', 'rot_matrix[1][2]', 'rot_matrix[1][3]', 'rot_matrix[2][1]', 'rot_matrix[2][2]', 'rot_matrix[2][3]', 'rot_matrix[3][1]', 'rot_matrix[3][2]', 'rot_matrix[3][3]']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_geometric_object_transformation kname: vector -> ['tr_vector[1]', 'tr_vector[2]', 'tr_vector[3]']

# -- multiple fkeys to same leaf table
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_multi_state_scheme_connectivity kname: ihm_multi_state_modeling -> ['begin_state_id', 'end_state_id']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_probe_list kname: ihm_chemical_component_descriptor -> ['probe_chem_comp_descriptor_id', 'reactive_probe_chem_comp_descriptor_id']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_struct_assembly_details kname: ihm_struct_assembly -> ['assembly_id', 'parent_assembly_id']

FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_derived_angle_restraint kname: ihm_feature_list -> ['feature_id_1', 'feature_id_2', 'feature_id_3']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_derived_dihedral_restraint kname: ihm_feature_list -> ['feature_id_1', 'feature_id_2', 'feature_id_3', 'feature_id_4']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_derived_distance_restraint kname: ihm_feature_list -> ['feature_id_1', 'feature_id_2']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_cross_link_list kname: entity_poly_seq -> ['comp_id_1', 'comp_id_2', 'entity_id_1', 'entity_id_2', 'seq_id_1', 'seq_id_2']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_cross_link_restraint kname: struct_asym -> ['asym_id_1', 'asym_id_2']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_cross_link_restraint kname: entity_poly_seq -> ['comp_id_1', 'comp_id_2', 'entity_id_1', 'entity_id_2', 'seq_id_1', 'seq_id_2']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_entity_poly_segment kname: entity_poly_seq -> ['comp_id_begin', 'comp_id_end', 'entity_id', 'seq_id_begin', 'seq_id_end']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_ordered_ensemble kname: ihm_model_group -> ['model_group_id_begin', 'model_group_id_end']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_ordered_model kname: ihm_model_group -> ['model_group_id_begin', 'model_group_id_end']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_poly_residue_feature kname: entity_poly_seq -> ['comp_id_begin', 'comp_id_end', 'entity_id', 'seq_id_begin', 'seq_id_end']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_predicted_contact_restraint kname: struct_asym -> ['asym_id_1', 'asym_id_2']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_predicted_contact_restraint kname: entity_poly_seq -> ['comp_id_1', 'comp_id_2', 'entity_id_1', 'entity_id_2', 'seq_id_1', 'seq_id_2']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_related_datasets kname: ihm_dataset_list -> ['dataset_list_id_derived', 'dataset_list_id_primary']
FKEY: WARNING: NOT FKEY. This is not an fkey tname:ihm_residues_not_modeled kname: entity_poly_seq -> ['comp_id_begin', 'comp_id_end', 'entity_id', 'seq_id_begin', 'seq_id_end']

# -- not fkeys
** FKEY: WARNING: NOT FKEY. This is not an fkey tname:chem_comp_atom kname: cartesian_coordinate -> ['model_Cartn_x', 'model_Cartn_y', 'model_Cartn_z', 'pdbx_model_Cartn_x_ideal', 'pdbx_model_Cartn_y_ideal', 'pdbx_model_Cartn_z_ideal'] --> not fkey
** FKEY: WARNING: NOT FKEY. This is not an fkey tname:chem_comp_atom kname: cartesian_coordinate_esd -> ['model_Cartn_x_esd', 'model_Cartn_y_esd', 'model_Cartn_z_esd'] --> not fkey
** FKEY: WARNING: NOT FKEY. This is not an fkey tname:entity_poly_seq kname: mm_poly_res_label -> ['entity_id', 'mon_id', 'num'] --> not fkey
    
** FKEY: WARNING: NOT FKEY. This is not an fkey tname:struct_ref_seq kname: entity_poly_seq -> ['seq_align_beg', 'seq_align_end'] --> doesn't exist corresponding key

TODO: BUG on table: ihm_cross_link_list, ihm_cross_link_restraint, ihm_poly_seqment, ihm_poly_residue_feature, ihm_predicted_contact_restraint,  ihm_residues_not_modeled
    """
    def extract_fkeys_hacks(self, tname, tdef, attr_id, cnames):
        """
        multi-fkeys mmcif defs e.g. a denormalized fkey list that consists of 1 or 2 fkeys grouped by prefix/suffix of the fkey names. See examples above.
        Split them into individual fkeys.
        """
        cdefs = self.get_cdefs(tdef)
        for cname in cnames:
            if "$ref" not in cdefs[cname].keys(): return None
        
        if tname == "entity_poly_seq" and set(cnames) == set(["entity_id", "mon_id", "num"]): 
            return # NOT FKEY OR KEY
        
        ref_tname = cdefs[cnames[0]]["$ref"][1:].split("/")[0]
        ref_cnames = [ cdefs[cname]["$ref"][1:].split("/")[1] for cname in cnames ]        
        fk_defs = {}
        joint = []
        fk = {}
        for cname in cnames:
            m1 = re.match("^(.*)_(beg|begin|end|1|2|3|4|primary|derived)$", cname)
            m2 = re.match("^(begin|end)_([^_]+)$", cname)
            m3 = re.match("^([^_]*)_?(assembly_id|probe_chem_comp_descriptor_id)$", cname)
            #print("**FKEY: WARNING: NOT FKEY. ATTEMPT HACKS. tname:%s kname: %s -> %s => cname:%s  m:%s" % (tname, attr_id, cnames, cname, m))
            if m1:
                fk.setdefault((m1[2], "suffix"), []).append(cname)
            elif m2:
                fk.setdefault((m2[1], "prefix"), []).append(cname)
            elif m3: 
                fk.setdefault((m3[1], "prefix"), []).append(cname)
            else:
                joint.append(cname)

        if len(fk.keys()) > 0:
            joint_ref_cnames = [ ref_cnames[cnames.index(c)] for c in joint ]
            for (gname, position), fk_cnames in fk.items():
                if position == "suffix": 
                    new_fk_name = f"{attr_id}_{gname}"
                else :
                    new_fk_name = f"{gname}_{attr_id}" if gname else attr_id
                new_cnames = joint + fk_cnames                
                new_ref_cnames = joint_ref_cnames + [ ref_cnames[cnames.index(c)] for c in fk_cnames ]
                fk_defs[new_fk_name] = (new_cnames, ref_tname, new_ref_cnames)
                #print("**FKEY: WARNING: NOT FKEY. ATTEMPT HACKS. tname:%s kname: %s -> %s => suffix:%s -> %s" % (tname, attr_id, cnames, suffix, fk_defs[f"{attr_id}_{suffix}"]))
                if set(["structure_id"]+new_ref_cnames) not in [ set(v) for v in self.mmcif_key_defs[ref_tname].values()]:
                    print("   - hacks: FKEY-DEF ERROR: FKEY_M1 - REF_KEY_NOT_EXIST: tname:%s fk: %s -> %s (%s) %s ==> klist(%s): %s" % (tname, new_fk_name, new_cnames, ref_tname, new_ref_cnames, ref_tname, self.mmcif_key_defs[ref_tname].values()))
                else:
                    print("   + hacks: FKEY-DEF: FKEY_M1 - REF_KEY_EXIST: tname:%s fk: %s -> %s (%s) %s ==> klist(%s): %s" % (tname, new_fk_name, new_cnames, ref_tname, new_ref_cnames, ref_tname, self.mmcif_key_defs[ref_tname].values()))                    
        
        return fk_defs

    # ---------------------------------------------------------------------------
    # combo2 which is the same as removing structure_id from fkey columns is no longer needed since Chaise
    # can now support proper display of optional fkey (e.g. as long as one column is null, fkey is null
    # TODO: when there are multiple fkeys to the same parent table, this is wrong
    def convert_to_combo_fkey(self, tname, cnames, fk_name, ref_tname, ref_cnames, is_optional=False, is_multi_fkey=False, remove_structure_id=False):
        """
        Convert fkey into optional fkey def by replacing structure_id with the leaf table RID.
        Also apply different strategy for naming RID column. 
        """
        # do not convert fkey to entry
        if ref_tname == "entry": return(fk_name, cnames, ref_cnames)

        if "entry_id" not in cnames and "structure_id" not in cnames:
            raise Exception("FKEY-DEF ERROR: either entry_id or structure_id has to be in the fkey def. tname:%s cnames:%s fk_name:%s ref_tname:%s ref_cnames:%s" % (tname, cnames, fk_name, ref_tname, ref_cnames))
        
        entry_key_cname = "entry_id" if "entry_id" in cnames else "structure_id"
        if remove_structure_id: # combo2
            new_cnames = cnames
            new_ref_cnames = ref_cnames
        else: # combo1
            new_cnames = cnames.copy()
            new_ref_cnames = ref_cnames.copy()
        
        new_fk_name = f"{fk_name}"
        entry_key_cname_index = cnames.index(entry_key_cname)
        new_cnames.pop(entry_key_cname_index)
        new_ref_cnames.pop(entry_key_cname_index)
        
        # strategy for rid_cname
        if is_multi_fkey:
            rid_cname = f"{new_fk_name.title()}_RID"        
        elif len(new_cnames) == 1 and new_cnames[0].endswith("_id"):
            rid_cname = "%s_RID" % (new_cnames[0].rsplit("_id")[0].title())
        else:
            #rid_cname = f"{ref_tname.title()}_RID"  # Doesn't work when there are multiple fkeys to the same table
            rid_cname = f"{fk_name.title()}_RID"            

        # add RID to fkeys
        new_cnames = [rid_cname]+cnames
        new_ref_cnames = ["RID"]+ref_cnames
        if ref_tname in ["ma_data", "software", "chem_comp"]:
            print("!!! convert_to_combo_fkey: tname: %s. checking existence of %s. cnames:%s fk_name:%s ref_tname:%s ref_cnames:%s key_def:%s" % (tname, new_ref_cnames, cnames, fk_name, ref_tname, ref_cnames, self.mmcif_key_defs[ref_tname]))
        else:
            print("@@@ convert_to_combo_fkey: tname: %s.  checking existence of %s. cnames:%s fk_name:%s ref_tname:%s ref_cnames:%s" % (tname, new_ref_cnames, cnames, fk_name, ref_tname, ref_cnames))
            pass
        
        # check whether the combo key is existing before adding
        if (tname, rid_cname, is_optional) in self.combo_rid_columns:
            print("CONVERT_TO_COMBO_FKEY: Deuplicate rid. tname: %s, rid_cname: %s, is_optional: %s" % (tname, rid_cname, is_optional)) # -- never happen
            raise Exception("DIE HERE")
        self.combo_rid_columns.add((tname, rid_cname, is_optional, ref_tname))
        if set(new_ref_cnames) not in [set(v) for v in self.mmcif_key_defs[ref_tname].values()]:
            kname = "primary_rid" if not remove_structure_id else "primary_combo2"
            self.mmcif_key_defs[ref_tname][(kname, "key")] = new_ref_cnames            
            if (ref_tname, kname, "key") not in self.combo_keys.keys():
                self.combo_keys[(ref_tname, kname, "key")] = new_ref_cnames
                print("  -- convert_to_combo_fkey: add to combo key: ref_tname: %s - %s -->" % (ref_tname, kname))
                #print(json.dumps( { f"{ref_tname}:{kname}:key" : v for (ref_tname, kname, suffix), v in self.combo_keys.items()}, indent=4))
                print(self.combo_keys)
            else:
                raise Exception("COMBO_FKEY ERROR: This is bad")
            if True or ref_tname in ["ma_data", "software", "chem_comp"]:
                print("  -> convert_to_combo_fkey: summary => tname:%s cnames:%s fk_name:%s ref_tname:%s ref_cnames:%s keys:%s" % (tname, new_cnames, new_fk_name, ref_tname, ref_cnames, self.mmcif_key_defs[ref_tname]))
        else:
            print("!!! convert_to_combo_fkey: tname: %s combo_key already exist: %s" % (tname, self.mmcif_key_defs[ref_tname]))
            #raise Exception("COMBO_FKEY ALREADY EXIST")

        return (new_fk_name, new_cnames, new_ref_cnames)
    # ---------------------------------------------------------------------------    
    # TODO: verify that only "structure_id is involved in mutiple fkeys
    """
    1. entry_id and structure_id exist (sruct, pdbx_entry_details, pdbx_database_status): Keep only one and use trigger to update the other or
      - create fkey(entry_id) -> (entry, [id]),
      - create fkey(entry_id, entry_RID) -> (entry, [id, rid])
      - creaet a trigger to automatically fill in structure_id
      - NOTE: In pdb_dev, only entry_id exist. 
    2. fkey(structure_id) 
      - create fkey(structure_id, structure_RID) -> (entry, [id, RID])
    3. fkey(col1, col2, ...) e.g. ihm_poly_residue_feature
      - if mandatory, create fkey(strucure_id, col1, col2, ...)
      - if optional, create fkey(<table_RID>, col1, col2, ...)
        - if there are multiple fkeys to the same table: address column naming e.g. <table>_RID_begin
    
    """
    def extract_mmcif_fkey_defs(self, tname, tdef, verbose=True):
        """
        Extract fkey definitions from the mmCIF model, adjust the fkeys so they are consistent (e.g. adding structure_id to fkey list).
        """
        cdefs = self.get_cdefs(tdef)
        ermrest_fkey_defs = []
        structure_denorm_fname = self.structure_id_Structure_RID_name
        entry_id_exists = False
        multi_fkeys = {}
        

        # -- go through $ref and _attribute_groups for initial book-keeping
        attr_id2cnames = {}
        for cname, cdef in cdefs.items():
            cdef_keys = cdef.keys()
            # -- Consolidate fkey to the same ref table
            if "$ref" in cdef_keys:
                (ref_tname, ref_cname) = cdef["$ref"][1:].split("/")
                # skip structure_id fkey. Prioritize entry_id
                if cname == "structure_id" and "entry_id" in cdefs.keys():
                    continue
                elif ref_tname != tname: #not self reference
                    # -- check composite fkeys flag TODO: Check!! 
                    if "_attribute_groups" in cdef_keys:
                        for group in cdef["_attribute_groups"]:
                            id = group["label"] if "label" in group.keys() else group["id"]
                            attr_id2cnames.setdefault(id, []).append(cname)
                    else:
                        attr_id2cnames.setdefault(ref_tname, []).append(cname)
                    #print("=FKEY_DEF : $REF tname: %s, %s -> %s, %s" % (tname, cname, ref_tname, ref_cname))
                else: 
                    if tname != "entry":
                        #print("FKEY_DEF ERROR: SELF_REFERENCE: Will ignore. tname: %s, %s -> %s, %s" % (tname, cname, ref_tname, ref_cname))
                        raise Exception("FKEY_DEF_ERROR: SELF_REFERENCE. tname: %s, %s -> %s, %s" % (tname, cname, ref_tname, ref_cname))

        # -- combine attribute groups into composite keys
        raw_fkey_defs = {}
        for attr_id, cnames in attr_id2cnames.items():
            if self.is_composite_fkey(tname, tdef, attr_id, cnames):
                ref_tname = cdefs[cnames[0]]["$ref"][1:].split("/")[0]
                ref_cnames = [ cdefs[cname]["$ref"][1:].split("/")[1] for cname in cnames ]
                if attr_id not in raw_fkey_defs.keys():
                    raw_fkey_defs[attr_id] = (cnames, ref_tname, ref_cnames)
                    #if verbose: print("- ATTR FKEY: NEW tname: %s, %s [%d] -> %s,  %s,  %s" % (tname, attr_id, len(cnames), cnames, ref_tname, ref_cnames))
            elif set(["structure_id", "entry_id"]).issubset(set(cnames)):
                ref_tname = cdefs[cnames[0]]["$ref"][1:].split("/")[0]
                ref_cnames = [ cdefs[cname]["$ref"][1:].split("/")[1] for cname in cnames ]
                # 2 fkey columns point to the same referenced column. Not allowed. Choose entry_id
                new_cnames = cnames.copy()
                new_cnames.remove("structure_id")
                new_ref_cnames = ref_cnames.copy()
                new_ref_cnames.pop(cnames.index("structure_id"))
                raw_fkey_defs[attr_id] = (new_cnames, ref_tname, new_ref_cnames)
                entry_id_exists = True
                if verbose: print(">>> FKEY_DEF ERROR: ENTRY_ID_STRUCTURE_ID_FKEY: can't have both be in fkey. Remove structure_id. tname:%s fk_name: %s, %s, %s -> %s ==> %s -> %s " % (tname, attr_id, cnames, ref_tname, ref_cnames, new_cnames, new_ref_cnames))
            else:
                if verbose: print(">>> FKEY: WARNING: NOT FKEY. Attempt to hack. This is not an fkey tname:%s kname: %s -> %s, klist(%s) -> %s" % (tname, attr_id, cnames, tname, self.mmcif_key_defs[tname]))
                fks = self.extract_fkeys_hacks(tname, tdef, attr_id, cnames)
                if fks:
                    if verbose: print("   >>> FKEY_DEF ERROR: NOT PROPER FKEY. Attemping hacks to split fkeys. tname:%s kname: %s -> %s. fks = %s" % (tname, attr_id, cnames, fks))
                    raw_fkey_defs.update(fks)
                    if len(fks) > 1:
                        multi_fkeys.update(fks)

        #print(json.dumps(raw_fkey_defs, indent=4))
        # -- adjust fkey list to address chaise and data integrity issues
        fkey_defs = {}
        for fk_name, (cnames, ref_tname, ref_cnames) in raw_fkey_defs.items():
            if tname == "entry": break
            if "structure_id" not in cdefs.keys() and "entry_id" not in cdefs.keys():
                raise Exception("FKEY_DEF_ERROR: STRUCTURE_ID_NOT_EXIST. tname: %s, fk:%s, %s" % (tname, fk_name, raw_fkey_defs[fk_name]))
            is_optional = self.are_all_optional_columns(tname, tdef, cnames, exclude_cnames=["structure_id", "Structure_RID", "entry_id"])
            
            # -- add structure_id to all fkeys except entry_id which point to entry/id.
            if "entry_id" in cdefs.keys():
                ref_structure_id_tname, ref_structure_id_cname = cdefs["entry_id"]["$ref"][1:].split("/")
            else:
                ref_structure_id_tname, ref_structure_id_cname = cdefs["structure_id"]["$ref"][1:].split("/")                
            if ref_structure_id_tname != "entry" or ref_structure_id_cname != "id":
                raise Exception("FKEY_DEF_ERROR: structure_id doesn't refer to 'entry/id' but '%s/%s' table" % (ref_structure_id_tname, ref_structure_id_cname))
            
            if ["entry_id"] == cnames: 
                # anchor entry_id with "Entry_RID" 
                new_fk_name = fk_name             # "entry_denorm"
                new_cnames = cnames               # cnames+["Entry_RID"]
                new_ref_cnames = ref_cnames
                """ # no need for Structure RID column
                if ref_tname == "entry":
                    new_ref_cnames =  ref_cnames + ["RID"] 
                elif "entry_id" in self.get_cdefs(self.get_tdef(self.mmcif, ref_tname)):
                    new_ref_cnames =  ref_cnames + ["Entry_RID"]
                elif "structure_id" in self.get_cdefs(self.get_tdef(self.mmcif, ref_tname)):
                    new_ref_cnames = ref_cnames + ["Structure_RID"]
                """
                if verbose: print("  **0.0 FKEY_DEF: ENTRY_ID FKEY: Add Entry_RID/RID  tname: %s,  %s [%d] -> %s ==> %s -> %s " % (tname, fk_name, len(cnames), raw_fkey_defs[fk_name], new_cnames, new_ref_cnames))
            elif "entry_id" in cdefs.keys() and "entry_id" not in cnames: # only one so far. e.g. ihm_entry_collection_mapping, but more in ma
                # add entry_id to fkey to make it distinct (similar to what we do with structure_id)
                new_fk_name = fk_name
                new_cnames = ["entry_id"] + cnames
                if "entry_id" in self.get_cdefs(self.get_tdef(self.mmcif, ref_tname)):
                    new_ref_cnames = ["entry_id"] + ref_cnames
                elif "structure_id" in self.get_cdefs(self.get_tdef(self.mmcif, ref_tname)):
                    new_ref_cnames = ["structure_id"] + ref_cnames
                else:
                    raise EXCEPTION("FKEY-ERROR: No corresponding entry_id or structure_id in the ref_table. tname: %s,  %s [%d] -> %s ==> %s -> %s " % (tname, fk_name, len(cnames), raw_fkey_defs[fk_name], new_cnames, new_ref_cnames))
                if verbose: print("  **0.1 FKEY_DEF: ENTRY_ID FKEY: Add entry_id   tname: %s,  %s [%d] -> %s ==> %s -> %s " % (tname, fk_name, len(cnames), raw_fkey_defs[fk_name], new_cnames, new_ref_cnames))
            elif ["structure_id"] == cnames:
                # anchor structure_id with Sturcture_RID
                new_fk_name = fk_name           # structure_denorm_fname
                new_cnames = cnames             #["structure_id", "Structure_RID"]
                new_ref_cnames = ref_cnames     #["id", "RID"]
                if verbose: print("  **2 FKEY_DEF: ADD_STRUCTURE_RID TO FKEY: tname: %s:%s, fk: %s: %s ==> %s -> %s" % (tname, fk_name, new_fk_name, raw_fkey_defs[fk_name], new_cnames, new_ref_cnames))
            elif "structure_id" not in cnames:
                # check for other entry key columns --> except a few tables, this shouldn't happen 
                if len(cnames) == 1 and ref_tname == ref_structure_id_tname and ref_cnames == [ref_structure_id_cname]:
                    raise Exception("FKE_DEF_ERROR: DUPLICATE_ENTRY_FKEY: Duplicate fkey to entry! tname: %s, %s -> %s. SKIP!!" % (tname, fk_name, new_fkey_defs[fk_name]))
                new_fk_name = fk_name
                new_cnames = ["structure_id"]+cnames
                new_ref_cnames = ["structure_id"]+ref_cnames
                if verbose: print("  **1 FKEY_DEF: MISSING_STRUCTURE_ID [optional=%s]: tname: %s,  %s [%d] -> %s. Add structure_id: %s -> %s" % (is_optional, tname, fk_name, len(cnames), raw_fkey_defs[fk_name], new_cnames, new_ref_cnames))
            # -- fkey:[structure_id] ==> turn into [structure_id, Structure_RID]
            elif "structure_id" in cnames:
                if is_optional:
                    raise Exception("FKEY_DEF_ERROR: UNEXPECTED OPTIONAL FKEY. mmCIF structure_id based key should not be optional.") # shouldn't exist
                new_fk_name = fk_name
                new_cnames = cnames
                new_ref_cnames = ref_cnames
                if verbose: print("  **2 FKEY_DEF: STRUCTURE_ID_INCLUDED (optiona=%s)]: tname: %s,  %s [%d] -> %s. Remain unchange" % (is_optional, tname, fk_name, len(cnames), raw_fkey_defs[fk_name]))
            else:
                raise Exception("FKEY_DEF_ERROR: UNKNOWN_FKEY:  tname: %s,  %s [%d] -> %s." % (tname, fk_name, len(cnames), raw_fkey_defs[fk_name]))

            #print("  **1 FKEY_DEF: DEBUG [optional=%s]: tname: %s,  %s [%d] -> %s. Add structure_id: %s -> %s" % (is_optional, tname, fk_name, len(cnames), raw_fkey_defs[fk_name], new_cnames, new_ref_cnames))
            
            # -- check keys before adding to the fkey_defs
            if set(new_ref_cnames) in [set(v) for v in self.mmcif_key_defs[ref_tname].values()]:
                # add parent table row RID with fkey
                is_multi_fkey = True if fk_name in multi_fkeys.keys() else False
                new_fk_name, new_cnames, new_ref_cnames =  self.convert_to_combo_fkey(tname, new_cnames, fk_name, ref_tname, new_ref_cnames, is_optional=is_optional, is_multi_fkey=is_multi_fkey)
                # add to fkey_defs    
                fkey_defs[new_fk_name] = (new_cnames, ref_tname, new_ref_cnames)
                if verbose: print("    -- FKEY_DEF: FKEY_ADDED_TO_LIST: tname:%s fk: %s: %s -> %s %s ==> klist: %s" % (tname, new_fk_name, new_cnames, ref_tname, new_ref_cnames, list(self.mmcif_key_defs[ref_tname].values())))
            else:
                # TODO: In this case, fix the original model manually?
                # FKEY_DEF ERROR: REF_KEY_NOT_EXIST: tname:struct_ref_seq_dif fk: entity_poly_seq: ['structure_id', 'mon_id', 'seq_num'] -> entity_poly_seq ['structure_id', 'mon_id', 'num'] ==> klist: [['structure_id', 'Structure_RID'], ['structure_id', 'entity_id', 'mon_id', 'num']]
                if verbose: print("    -- FKEY_DEF ERROR: REF_KEY_NOT_EXIST: tname:%s fk: %s: %s -> %s %s ==> klist: %s" % (tname, new_fk_name, new_cnames, ref_tname, new_ref_cnames, list(self.mmcif_key_defs[ref_tname].values())))
                pass

        return fkey_defs
        
    # ---------------------------------------------------------------------------        
    def get_ermrest_fkey_defs(self, tname, tdef, verbose=True):
        """
        Return ermrest forieng key definitions related to this table
        """
        cdefs = self.get_cdefs(tdef)
        fkey_defs = self.mmcif_fkey_defs[tname] if tname in self.mmcif_fkey_defs.keys() else self.extract_mmcif_fkey_defs(tname, tdef)        
        ermrest_fkey_defs = []

        # -- create ermrest fkey
        cname2fkeys={}     # check for columns that participlate in multiple fkeys
        if verbose: print("== eFKEYS [%d]: tname: %s  fkeys: " % (len(fkey_defs.keys()), tname))
        for fk_name, (cnames, ref_tname, ref_cnames) in fkey_defs.items():
            for cname in cnames:
                cname2fkeys.setdefault(cname, []).append(fk_name)
            is_optional = self.are_all_optional_columns(tname, tdef, cnames, exclude_cnames=["structure_id", "Structure_RID", "entry_id"])

            # TODO: captitalized fk_name, column name appropriately??
            if verbose: print("  x FKEY: tname: %s, fk: %s [%d] [optional=%s] -> %s,  %s,  %s" % (tname, fk_name, len(cnames), is_optional, cnames, ref_tname, ref_cnames))

            # -- check identifier lengh
            constraint_name = f"{tname}_{fk_name}_fkey"
            if len(constraint_name) >= self.identifier_limit:
                if verbose: print("    - FKEY ERROR: LENGTH_ERROR: tname: %s, fk: %s [%d] -> %s,  %s,  %s" % (tname, constraint_name, len(cnames), cnames, ref_tname, ref_cnames))
                constraint_name = self.shorten_constraint_name(tname, fk_name, "fkey")
            
            # -- create ermrest fkey
            ermrest_fkey_defs.append(
                ForeignKey.define(cnames, self.domain_schema_name, ref_tname, ref_cnames,
                                  constraint_names=[[self.domain_schema_name, constraint_name]],
                                  on_update="CASCADE",
                                  on_delete="SET NULL"   
                                  ),
            )

        # check for columns participating in multiple fkeys.. 
        for cname, fkeys in cname2fkeys.items():
            if len(fkeys) > 1 and cname != "structure_id":
                print("******* eFKEY MULTI-FKEY tname: %s column: %s [%d] -> %s" % (tname, cname, len(fkeys), fkeys))
        # fkey
        return ermrest_fkey_defs

    # ---------------------------------------------------------------------------
    # TODO: TO DELETE
    def get_ermrest_vocab_fkey_defs_orig(self, tname, tdef, verbose=True):
        """
        Extract and create ermrest fkey definitions based on the enum columns in the mmCIF table definition.
        """
        if verbose: print("==v VOCAB FKEY : tname: %s " % (tname))
        cdefs = self.get_cdefs(tdef)
        ermrest_vocab_fkey_defs=[]
        for cname, cdef in cdefs.items():
            if "enum" not in cdef.keys(): continue
            common_vocab_table = self.search_for_common_vocab_table(cdef["enum"])
            if common_vocab_table and self.apply_common_vocab:
                vocab_tname = common_vocab_table
            else:
                vocab_tname = "%s_%s" % (tname, cname)
            constraint_name = self.shorten_constraint_name(tname, cname, "fkey")
            if len(constraint_name) > self.identifier_limit:
                raise Exception("FKEY ERROR: LENGTH_ERROR: fkey constraint name is too long: tname: %s constraint_name: %s[%d]" % (tname, constraint_name, len(constraint_name)))
            
            ermrest_vocab_fkey_defs.append(
                ForeignKey.define([cname], self.vocab_schema_name, vocab_tname, ["Name"],
                                  constraint_names=[[self.domain_schema_name, constraint_name]],
                                  on_update="CASCADE",
                                  on_delete="SET NULL"   
                                  ),
            )
                
        return(ermrest_vocab_fkey_defs)

    # ---------------------------------------------------------------------------
    def get_ermrest_vocab_fkey_defs(self, tname, tdef, verbose=True):
        """
        Extract and create ermrest fkey definitions based on the enum columns in the mmCIF table definition.
        """

        if verbose: print("==v VOCAB FKEY : tname: %s " % (tname))
        cdefs = self.get_cdefs(tdef)
        ermrest_vocab_fkey_defs=[]
        for cname, cdef in cdefs.items():
            if "enum" not in cdef.keys(): continue
            common_tname, common_cname = self.search_for_common_vocab_table(cdef["enum"])
            if common_tname and self.apply_common_vocab:
                vocab_tname = common_tname
                vocab_cname = common_cname
                print("get_ermrest_vocab_fkey_defs: enum: %s -> tname: %s, cname: %s" % (cdef["enum"], common_tname, common_cname))
            else:
                vocab_tname = "%s_%s" % (tname, cname)
                vocab_cname = "Name"
            constraint_name = self.shorten_constraint_name(tname, cname, "fkey")
            if len(constraint_name) > self.identifier_limit:
                raise Exception("FKEY ERROR: LENGTH_ERROR: fkey constraint name is too long: tname: %s constraint_name: %s[%d]" % (tname, constraint_name, len(constraint_name)))
            
            ermrest_vocab_fkey_defs.append(
                ForeignKey.define([cname], self.vocab_schema_name, vocab_tname, [vocab_cname],
                                  constraint_names=[[self.domain_schema_name, constraint_name]],
                                  on_update="CASCADE",
                                  on_delete="SET NULL"   
                                  ),
            )
                
        return(ermrest_vocab_fkey_defs)
            
    
    # ---------------------------------------------------------------------------
    def get_ermrest_vocab_table_defs(self, tname, tdef):
        """
        Extract and create ermrest table definitions based on the enum columns in the mmCIF table definition.
        The function excludes enum tables that have the same content has one of the common vocab tables.
        """
        cdefs = self.get_cdefs(tdef)
        ermrest_vocab_tdefs={}
        for cname, cdef in cdefs.items():
            if "enum" not in cdef.keys(): continue
            ctype = self.mmcif_to_ermrest_type(cdef["type"])
            if self.search_for_common_vocab_table(cdef["enum"])[0] and self.apply_common_vocab: continue
            #vocab_tname = "%s_%s" % (tname, cname)
            vocab_tname = self.shorten_constraint_name(tname, cname, "")            
            tcomment=cdef["description"] if "description" in cdef.keys() else None
            
            if  False or tname == "ma_poly_template_library_details":
                print("VOCAB_TABLE: tname:%s enum:%s vocab_tname:%s [%d]" % (tname, cname, vocab_tname, len(vocab_tname)))


            if (len(vocab_tname) > self.identifier_limit):
                raise Exception("TABLE ERROR: LENGTH_ERROR: table name is too long: %s[%d]" % (vocab_tname, len(vocab_tname)))
            ermrest_vocab_tdefs[(tname, cname)] = create_vocab_tdoc(self.vocab_schema_name, vocab_tname, tcomment, False, name_type=ctype)
        return(ermrest_vocab_tdefs)


    # ---------------------------------------------------------------------------
    def get_enum_dict(self, tname, cname):
        """
        Get a list of enum terms from the mmcif model
        """
        tdef = self.get_tdef(self.mmcif, tname)
        cdef = self.get_cdef(tdef, cname)
        if "enum" not in cdef.keys(): return None
        terms = { e : {"Name": e, "Description": None} for e in cdef["enum"] }    
        if "rcsb_enum_annotated" in cdef.keys():
            if len(cdef["rcsb_enum_annotated"]) != len(cdef["enum"]):
                print("ENUM_ERROR: %s:%s Expected rcsb_enum_annotated to have the same length as enum" % (tname, cname))
            for ann in cdef["rcsb_enum_annotated"]:
                # TODO: replace "\n    " with " "
                if "detail" in ann.keys(): terms[ann["value"]]["Description"] = ann["detail"].strip().replace("\n                                  ", " ")
        return terms

    # ---------------------------------------------------------------------------
    # TODO: Address the common vocab tables
    def populate_vocab_tables(self, catalog):
        """
        Populate the vocabulary tables. Fir common tables, the normal vocab tables.
        """
        print("\n--- populate_vocab_tables ---")
        # create payload for common vocab table
        common_tname2cnames = {}
        common_tname2payload = {}
        for (tname, cname) in self.common_vocab_table_dict.keys():
            common_tname2cnames.setdefault(tname, []).append(cname)
            
        for tname, cnames in common_tname2cnames.items():
            payload = common_tname2payload.setdefault(tname, [])
            num_rows = len(self.common_vocab_table_dict[(tname, cnames[0])])
            for i in range(0,num_rows):
                enum_dict = {"Description": None}
                for n in cnames:
                    enum_dict[n] = self.common_vocab_table_dict[(tname, n)][i]
                payload.append(enum_dict)
            print("vocab_tname: %s ==> %s " % (tname, payload))
            insert_if_not_exist(catalog, self.vocab_schema_name, tname, payload)
    
        # iterate over vocab tables (non-common) to get payload and update ermrest
        for (tname, cname), ermrest_tdef in self.ermrest_vocab_tables.items():
            print("tname: %s, cname: %s" % (tname, cname))
            if cname is None: continue
            enum_dict = self.get_enum_dict(tname, cname)
            vocab_tname = ermrest_tdef["table_name"]
            payload = list(enum_dict.values())
            print("vocab_tname: %s ==> %s " % (vocab_tname, payload))
            insert_if_not_exist(catalog, self.vocab_schema_name, vocab_tname, payload)


# =========================================================================================
def create_ermrest_schema(catalog, sname, schema_doc):
    resp = catalog.post(
        "/schema",
        json={
            "schemas": {
                sname: schema_doc
            }
        })
    return resp

# =========================================================================================    
def check_out_mmcif_dict(mmcif_fname):
    global mmcif
    
    # Opening JSON file
    with open(mmcif_fname) as json_file:
        mmcif = json.load(json_file)
    json_file.close()
    
    table_types = {
        "object": [],
        "array": [],
    }
    table_properties = set()
    item_properties = set()
    column_properties = set()
    for tname, tdef in mmcif["properties"].items():
        for k, v in tdef.items():
            table_properties.add(k)
            if k == "items":
                for i in tdef["items"]:
                    item_properties.add(i)
        ttype = tdef["type"]
        if ttype not in table_types.keys():
            table_types[tdef["type"]] = []
        table_types[tdef["type"]].append(tname)
        cdefs = tdef["items"]["properties"] if ttype == "array" else tdef["properties"]
        for cname, cdef in cdefs.items():
            for k,v in cdef.items():
                column_properties.add(k)

    #print(json.dumps(table_types, indent=2))
    #print(table_properties)
    #print(item_properties)        
    #print(column_properties)
    

    
# =========================================================================================
def main(args):
    credentials = get_credential(args.host, args.credential_file)    
    catalog = ErmrestCatalog("https", args.host, args.catalog_id, credentials)
    catalog.dcctx['cid'] = "model"
    store = HatracStore("https", args.host, credentials)
    model = catalog.getCatalogModel()

    compare_models(model, args.model_docs, output_dir)
    return

    #model.schemas["MA"].drop(cascade=True)
    
    mmcif_ermrest_model = mmCIFErmrestModel(args.model_docs, "MA", "Vocab")
    dump_json_to_file(f"{args.output_dir}/schema_ma.json", mmcif_ermrest_model.ermrest_domain_schema)    
    dump_json_to_file(f"{args.output_dir}/schema_vocab.json", mmcif_ermrest_model.ermrest_vocab_schema)

    if args.dry_run:
        return

    if "Vocab" not in model.schemas.keys():
        create_ermrest_schema(catalog, "Vocab", mmcif_ermrest_model.ermrest_vocab_schema)

    if "MA" not in model.schemas.keys():        
        create_ermrest_schema(catalog, "MA", mmcif_ermrest_model.ermrest_domain_schema)
        
    mmcif_ermrest_model.populate_vocab_tables(catalog)


'''

python -m config-scripts.model-changes.initial.process_mmcif_model --model-docs config-scripts/model-changes/initial/ma-min-db-schema.json --dry-run

'''
if __name__ == "__main__":
    cli = ConfigCLI("extras", None, 1)
    cli.parser.add_argument('--model-docs', help="json schema docs representing mmCIF dict", default="ma-min-db-schema.json")
    cli.parser.add_argument('--output-dir', help='Directory for output files', default='/scratch/ma')
    args = cli.parse_cli()
    
    main(args)

