#!/usr/bin/python

import sys
import json
from deriva.core import ErmrestCatalog, AttrDict, get_credential, DEFAULT_CREDENTIAL_FILE, tag, urlquote, DerivaServer, get_credential, BaseCLI
from deriva.core.ermrest_model import builtin_types, Schema, Table, Column, Key, ForeignKey
from deriva.core import urlquote, urlunquote
from deriva.core import HatracStore
import requests.exceptions
import re
from .model import ermrest_groups, humanize_groups, humanize_acls
from .shared import ConfigCLI, DCCTX, cfg

globus_id_prefix="https://auth.globus.org"

# ============================================================================
# add /dev prefix to namespace in the development environment. 
def adjust_hatrac_namespace(namespace, hatrac_root='/hatrac'):
    """Adjust Hatrac namespace in case the server contains multiple environments.
    
    In the case that there are multiple catalogs on the same server sharing the same hatrac store,
    each catalog needs a different hatrac prefix. This function address the co-existence of dev.
    For example: when a dev and staging catalog co-exist, the dev namespace will have
    /hatrac/dev as a prefix, while staging will have /hatrac as a prefix.

    Args:
        namespace (str): Hatrac namespace referring to
        hatrac_root (str): Hatrac root to be used. The default is /hatrac

    Returns:
        str: Adjusted hatrac root. 
    
    """
    if not namespace.startswith(hatrac_root):
        namespace = namespace.replace("/hatrac", hatrac_root, 1)
        
    return namespace

    
# ==============================================================================
# functions for managing acls
#
# -- ---------------------------------------------------------------------
# set one hatrac namespace acl
def set_hatrac_namespace_acl(store, acl, namespace, hatrac_root='/hatrac', verbose=False):
    """Set acl to one Hatrac namespace.

    Args:
        store (obj): Hatrac store
        acl (obj): Hatrac ACL
        namespace (str): Hatrac namespace
        hatrac_root: the Hatrac root prefix to be used

    Note: hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'
    
    """
    namespace = adjust_hatrac_namespace(namespace, hatrac_root)
    if verbose: print("  INFO: set_hatrac_namespace_acl: %s, acl: %s"  % (namespace, humanize_acls(acl)))
    try :
        if not store.is_valid_namespace(namespace):
            print("INFO: %s is not a valid namespace" % (namespace))
            return
    except Exception as e:
        if verbose: print("EXCEPTION %s: %s " % (namespace, e))
        return
        
    for access, roles in acl.items():
        if verbose: print("    - namespace: %s seting access %s = %s" % (namespace, access, humanize_groups(roles)))
        store.set_acl(namespace, access, roles)
            
    if False:
        try :
            print("-- set rcb_access %s: %s" % (namespace, json.dumps(store.get_acl(namespace), indent=2) ))
        except Exception as e:
            pass
        
# -- ---------------------------------------------------------------------
# set acl for a list of namespaces
def set_hatrac_namespaces_acl(store, acl, namespaces, hatrac_root='/hatrac', verbose=False):
    """Set acl to a list of namespaces.

    Args:
        store (obj): Hatrac store
        acl (obj): Hatrac ACL
        namespaces (list): Hatrac namespaces 
        hatrac_root: the Hatrac root prefix to be used
    
    Note: hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'
    """
    if verbose: print("======= set_hatrac_namespaces_acl: %s =======" % (namespaces))    
    for namespace in namespaces:
        set_hatrac_namespace_acl(store, acl, namespace, hatrac_root)
        
# --------------------------------------------------------------------
# set hatrac read access based on user folders
# NOTE: DO NOT SET OWNER. LET SQL SCRIPT DEAL WITH IT
def set_hatrac_read_per_user(store, parent_namespaces, hatrac_root='/hatrac', verbose=False):
    """
    Assuming that globus userid (uid) is used as part of the namespace. This function removes the existing
    owner of the child namespace and grants read access to the corresponding globus user assiciated with the uid.
    The script blindly assume uid is a globusid. 
    param:
      - parent_namespaces: the namespace containing different uids e.g. /hatrac/pdb/generated/uid

    Note: hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'
    """
    print("======= set_hatrac_read_per_user: %s =======" % (parent_namespaces))        
    for parent in parent_namespaces:
        parent = adjust_hatrac_namespace(parent, hatrac_root)
        try:
            uid_namespaces = store.retrieve_namespace(parent)
            print(" - UID: %s" % (uid_namespaces))
            for uid_namespace in uid_namespaces:
                uid = uid_namespace.replace(parent+"/", "")
                user_id = "%s/%s" % (globus_id_prefix, uid)
                acl = {
                    "subtree-read": [user_id]
                }
                set_hatrac_namespace_acl(store, acl, uid_namespace, hatrac_root)
        except Exception as e:
            print("NO node to set READ per user at: %s, %s" % (parent, e))
    

# --------------------------------------------------------------------
# set hatrac read access based on user folders.
# Note: We no longer need to execute this in python script since it will be
# taken care of in the hourly cron job. 
def set_hatrac_write_per_user(store, parent_namespaces, hatrac_root='/hatrac'):
    """
    Assuming that globus userid (uid) is used as part of the namespace. This function removes the existing
    owner of the child namespace and grants read/write access to the corresponding user assiciated with the uid. 
    param:
      - parent_namespaces: the namespace containing different uids e.g. /hatrac/pdb/sbumitted/uid

    Note: hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'
    
    """
    print("======= set_hatrac_write_per_user: %s =======" % (parent_namespaces))        
    for parent in parent_namespaces:
        parent = adjust_hatrac_namespace(parent, hatrac_root)
        try:
            uid_namespaces = store.retrieve_namespace(parent)
            print(" - UID: %s" % (uid_namespaces))
            for uid_namespace in uid_namespaces:
                uid = uid_namespace.replace(parent+"/", "")
                user_id = "%s/%s" % (globus_id_prefix, uid)  
                acl = {
                    "owner": [],
                    "subtree-owner": [],
                    "create": [user_id],
                    "subtree-create": [user_id],
                    "subtree-update": [user_id],            
                    "subtree-read": [user_id]
                }
                set_hatrac_namespace_acl(store, acl, uid_namespace, hatrac_root)
        except Exception as e:
            print("NO node to set WRITE per user at: %s, %s" % (parent, e))

            
# -- ---------------------------------------------------------------------
# In case the namespaces (non-objects) are owned by submitters
# !!!
# NOTE: THE HATRAC APIS ARE NOT WORKING AS INTENDED. DO NOT CALL THIS FOR NOW.
# !!!
def reset_namespaces_owners(store, hatrac_root='/hatrac'):
    """
    Remove existing acls from the subtree.

    Note: hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'
    
    """
    namespaces = []
    rootns = hatrac_root
    namespaces.extend(store.retrieve_namespace(rootns))

    while namespaces:
        ns = namespaces.pop(0)
        if store.is_valid_namespace(ns):
            print("+++++++++++++ ns: %s ++++++++++++" % (ns))
            roles = store.get_acl(ns, "owner")
            if roles:
                store.del_acl(ns, "owner", None)
            namespaces.extend(store.retrieve_namespace(ns))
            print("--- %s: reset owner: %s ---" % (ns, roles))
    

# =====================================================================
# functions to manage namespaces
#
# -- ---------------------------------------------------------------------
# create one hatrac namespace
def create_hatrac_namespace_if_not_exist(store, namespace, hatrac_root='/hatrac', verbose=False):
    """Create the provided namespace if not exist.

    Args:
        store (object): Hatrac store
        namespace (string): A namespace to be created

    Note:
        hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'
    
    """
    namespace = adjust_hatrac_namespace(namespace, hatrac_root)

    if store.is_valid_namespace(namespace):
        return
    else:
        if verbose: print("CREATE NAMESPACE: %s " % (namespace))
        store.create_namespace(namespace, parents=True)
        
        
# -- ---------------------------------------------------------------------
# create a set of hatrac namespaces
def create_hatrac_namespaces_if_not_exist(store, namespaces, hatrac_root='/hatrac'):
    """
    Create a list of namespace if not exist.

    Args:
        store (object): Hatrac store
        namespaces (list): A list of namespaces to be created

    Note: hatrac_root is used to adjust the hatrac namespace prefix, for example,
    in the case the dev and staging are deployed to the same environment,
    the dev env for hatrac will be deployed to '/hatrac/dev' instead of '/hatrac'

    """
    for namespace in namespaces:
        create_hatrac_namespace_if_not_exist(store, namespace, hatrac_root)


# -- ==============================================================================================
def main(server_name, catalog_id, credentials, args):
    server = DerivaServer("https", server_name, credentials)
    catalog = server.connect_ermrest(catalog_id)
    catalog.dcctx["cid"] = DCCTX["acl"]
    store = HatracStore('https', server_name, credentials)
    
    """
    1. Create a namespace of a user if not exist
    2. Set sub-tree read for a user
    """
    user_id = 'https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b' # isrd_staff
    uuid = user_id.rsplit("/", 1)[1]
    namespace_prefix="/hatrac/ihmv/generated/uid"
    namespace = f"{namespace_prefix}/{uuid}"
    create_hatrac_namespaces_if_not_exist(store, [namespace], hatrac_root=cfg.hatrac_root)
    acl = { "subtree-read": [ user_id ] }
    set_hatrac_namespace_acl(store, acl, namespace, hatrac_root=cfg.hatrac_root)
    print("Namespace is created and assigned acl")
    
    return 0

# -- ==============================================================================================
# to run the script:
# to get history:
#   python -m pdb_dev.utils.history --host data.pdb-dev.org --catalog-id 1 --rid 2-TK8P
# to get snapshot version:
#   python -m pdb_dev.utils.history --iso2snap --iso-datetime <RMT>
#
if __name__ == '__main__':
    cli = ConfigCLI("hatrac_acl", None, 1)
    #cli.parser.add_argument('--schema', metavar='<schema>', help="Schama name (default=PDB)", default="PDB", required=False)
    args = cli.parse_cli()
    credentials = get_credential(args.host, args.credential_file)
    
    sys.exit(main(args.host, args.catalog_id, credentials, args))
        
