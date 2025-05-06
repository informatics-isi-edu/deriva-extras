#!/usr/bin/python

import os
import json
from deriva.core import PollingErmrestCatalog, HatracStore, init_logging, urlquote, get_credential
import subprocess
import logging
import sys
import traceback

from deriva.utils.extras.data import insert_if_not_exist, get_ermrest_query, delete_table_rows
from deriva.utils.extras.model import create_vocabulary_tdoc, create_vocab_tdoc, create_table_if_not_exist, create_schema_if_not_exist
from deriva.utils.extras.shared import DCCTX, ConfigCLI, cfg


class DispatcherRuntimeError (RuntimeError):
    pass

class DispatcherNotReadyError (RuntimeError):
    pass

class DispatcherBadDataError (RuntimeError):
    pass


# ===================================================================================
# logformatter = logging.Formatter('%(name)s[%(process)d.%(thread)d]: %(message)s')

def init_logger(log_level="info", log_file="/tmp/log/processor.log"):
    """
    Set logger. This should only be called once for every process
    """
    __LOGLEVEL = {
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
    log_dir = log_file.rsplit("/", 1)[0]
    os.system(f'mkdir -p {log_dir}')
    format = '- %(asctime)s: %(levelname)s <%(module)s>: %(message)s'
    
    logger = logging.getLogger(__name__)
    handler=logging.handlers.TimedRotatingFileHandler(log_file, when='D', backupCount=7)
    log_level = __LOGLEVEL[log_level]
    logger.addHandler(handler)    
    handler.setFormatter(logging.Formatter(format))
    logger.setLevel(log_level)
    if file_path: 
        init_logging(level=log_level, log_format=format, file_path=log_file)
    else:
        init_logging(level=log_level, log_format=format)
    logger.info("************************ init logger ************************")
    return(logger)

# =================================================================================================
# claim_input_data=lambda row: {'RID': row['RID'], 'Processing_Status': "In-progress", 'Status_Detail': None},
class JobStream (object):
    def __init__(
            self,
            get_claimable_url,
            put_claim_url,
            put_update_baseurl
    ):
        self.get_claimable_url = get_claimable_url
        self.put_claim_url = put_claim_url
        self.put_update_baseurl = put_update_baseurl
        self.idle_etag = None

    def run_row_job(self, dispatcher, row):
        # TO BE OVERWRITE BY SUBCLASSES
        raise NotImplementedError("run_row_job needs to be overwritten")

    def run_batch_job(self, dispatcher, batch):
        '''
        row : the row that is claimed
        claim: the json array of values that was used during the claiming process
        '''
        for row, claim in batch:
            try:
                dispatcher.logger.info('\nClaimed job %s.' % row.get('RID'))
                self.run_row_job(dispatcher, row) # need to pass dispatcher
            except DispatcherBadDataError as e:
                dispatcher.logger.error("Aborting task %s on data error: %s\n" % (row["RID"], e))
                dispatcher.catalog.put(self.put_claim_url, json=[self.failure_input_data(row, e)])
                # continue with next task...?
            except DispatcherRuntimeError as e:
                dispatcher.logger.error("Aborting task %s on data error: %s\n" % (row["RID"], e))
                dispatcher.catalog.put(self.put_claim_url, json=[self.failure_input_data(row, e)])
                # continue with next task...?
            except Exception as e:
                dispatcher.catalog.put(self.put_claim_url, json=[self.failure_input_data(row, e)])
                raise
    
    def claim_input_data(self, row):
        return {'RID': row['RID'], 'Processing_Status': "In-progress", 'Status_Details': None}

    def failure_input_data(self, row, e):
        return  {'RID': row['RID'], 'Processing_Status': "Error", 'Status_Details': e}    


# ---------------------------------------------------------------------------------
# EXPERIMENTAL: not needed
class Job(object):
    def __init__(self, row, job_stream):
        self.row = row
        self.job_stream = stream

    
# =================================================================================================
# ERMREST_SERVER=aixbio-dev.derivacloud.org CATALOG_ID=99 python structure_worker.py
class JobDispatcher (object):
    job_streams = []   

    def __init__(self, deriva_host, catalog_id, credential_file=None, poll_seconds=300, config_file=None, logger=None):
        # -- initiate ermrest
        self.deriva_host = deriva_host
        self.catalog_id = catalog_id
        self.credential_file = credential_file
        self.credentials = get_credential(self.deriva_host, self.credential_file)  
        print("credential: %s" % (self.credentials))
        self.poll_seconds = poll_seconds
        self.config_file = config_file  # os.getenv('CONFIG', '/home/aixbio/config/processing/conf.json')
        # these are peristent/logical connections so we create once and reuse
        # they can retain state and manage an actual HTTP connection-pool
        self.catalog = PollingErmrestCatalog(
            'https', 
            self.deriva_host,
            self.catalog_id,
            self.credentials
        )
        self.catalog.dcctx['cid'] = 'pipeline'
        self.logger = logger
        self.logger.info("--- JobDispatcher: init")
        self.store = HatracStore('https', self.deriva_host, self.credentials)
        
    def look_for_work(self):
        """Find, claim, and process work for each work unit.

        Do find/claim with HTTP opportunistic concurrency control and
        caching for efficient polling and quiescencs.

        On error, set Process_Status="failed: reason"

        Result:
         true: there might be more work to claim
         false: we failed to find any work
        """
        found_work = False

        for stream in self.job_streams:
            # this handled concurrent update for us to safely and efficiently claim a record
            # batch is an array of (row, claim_input_data) where claim_input_data is a function to set claimed values
            try:
                stream.idle_etag, batch = self.catalog.state_change_once(
                    stream.get_claimable_url,
                    stream.put_claim_url,
                    stream.claim_input_data,
                    stream.idle_etag
                )
            except Exception as e:
                # keep going if we have a broken WorkUnit
                et, ev, tb = sys.exc_info()
                sys.stderr.write('Looking for job: got unexpected exception "%s"\n' % str(ev))
                self.logger.error('Looking for job: got unexpected exception "%s"' % str(ev))
                self.logger.error('%s' % ''.join(traceback.format_exception(et, ev, tb)))
                continue
            # batch may be empty if no work was found...
            if batch:
                found_work = True
                try:
                    stream.run_batch_job(self, batch) # need to pass dispatcher
                except Exception as e:
                    # TODO: consider iterate over the batch to log error, or let the batch handler deals with it
                    #self.catalog.put(stream.put_claim_url, json=[stream.failure_input_data(row, e)])
                    raise
        return found_work

    def blocking_poll(self, job_streams):
        self.job_streams = job_streams
        return self.catalog.blocking_poll(self.look_for_work, polling_seconds=self.poll_seconds)


# =================================================================================
class ExampleJobStream (JobStream):
    def __init__(self,  get_claimable_url, put_claim_url, put_update_baseurl):
        super().__init__(get_claimable_url, put_claim_url, put_update_baseurl)
                       
    def run_row_job(self, dispatcher, row):
        assert row['RID'] 
        scratch_dir = "/tmp/myproject"

        print("execution_run_row_job: begin task %s" % (json.dumps(row, indent=4)))
        print("Running a row with rid: %s" % (row["RID"]))
        # TODO: call the specific processor
        # Processor(dispatcher.catalog, dispatcher.store, scratch_dir=scratch_dir).run(rid)

    # TODO: update the row details to clain the row
    def claim_input_data(self, row):
        return {'RID': row['RID'], 'Process_Status': 'In-progress', 'Record_Status_Details': None}

    # TODO: update the row details if something is wrong during execution
    def failure_input_data(self, row, e):
        return  {'RID': row['RID'], 'Process_Status': 'Error', 'Record_Status_Details': e}    
        


# =================================================================================
# To run:
# > python job_dispatcher.py --host data-dev.pdb-ihm.org --catalog-id 99 --rid 1234
# Note: this script will not end as it keeps looping forever


def main(args):
    DESC = "Processing worker"
    INFO = "For more information see: https://github.com/informatics-isi-edu/aixbio"

    print("args: %s" % (args))
    
    dispatcher = JobDispatcher(args.host, args.catalog_id, args.credential_file, logger=logger)
    job_streams = [ ExampleJobStream(
        '/entity/M:=PDB:entry/Workflow_Status=any(New,In-progress)?limit=1',
        '/attributegroup/PDB:entry/RID;Execution_Status,Status_Details',
        '/attributegroup/PDB:entry/RID',
    ) ]
    dispatcher.blocking_poll(job_streams)
    return 0

# =================================================================================
if __name__ == '__main__':
    args = ConfigCLI("extras", None, 1).parse_cli()
    credentials = get_credential(args.host, args.credential_file)

    sys.exit(main(args))
    
