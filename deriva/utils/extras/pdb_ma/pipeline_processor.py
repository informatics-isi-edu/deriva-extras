# Copyright 2020 University of Southern California
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import subprocess
import sys
import traceback
import shutil
import smtplib
from email.mime.text import MIMEText
import mimetypes
import socket
from socket import gaierror, EAI_AGAIN
import json
import tempfile
import filecmp
import logging
import logging.handlers
import time
from datetime import datetime as dt, timedelta, timezone
import pytz

from deriva.core import PollingErmrestCatalog, HatracStore, urlquote, get_credential, DerivaServer, BaseCLI, init_logging
from deriva.utils.extras.data import insert_if_not_exist, update_table_rows, delete_table_rows, get_ermrest_query
from deriva.utils.extras.hatrac import HatracFile
from deriva.utils.extras.shared import ConfigCLI, DCCTX, cfg
from deriva.utils.extras.job_dispatcher import init_logger

logger = logging.getLogger(__name__)

# ===================================================================================
# logformatter = logging.Formatter('%(name)s[%(process)d.%(thread)d]: %(message)s')
def set_logger(loglevel=logging.DEBUG, log_file="/tmp/log/processor.log"):
    """
    Set logger. This should only be called once for every process
    """
    handler=logging.handlers.TimedRotatingFileHandler(log_file, when='D', backupCount=7)
    format = '- %(asctime)s: %(levelname)s <%(module)s>: %(message)s'
    handler.setFormatter(logging.Formatter(format))
    logger.addHandler(handler)
    logger.setLevel(loglevel)
    init_logging(level=loglevel, log_format=format, file_path=log_file)


# ===================================================================================
# different error classes 

class ProcessingError(Exception):
    """ Exception when fail to perform processing
    """
    pass

class ErmrestError(ProcessingError):
    """ Exception when fail to perform transaction with Ermrest
    """
    pass
    
class ErmrestUpdateError(ErmrestError):
    """ Exception when fail to update to Ermrest
    """
    pass

class FileError(ProcessingError):
    """ Exception when fail to read or write files
    """
    pass


# ===================================================================================
class PipelineProcessor(object):
    """
    PipelineProcessor base class that set common variables and shared functions
    """
    python_bin = "/usr/bin/python3"    
    cutoff_time_pacific = "Thursday 20:00"    
    release_time_utc = "Wednesday 00:00"      # In UTC, so we don't have to address day light saving time.
    timeout = 30                              # minutes
    email_config = None                       # e.g. "/home/pdbihm/.secrets/mail.json"
    log_dir = "/tmp/log"
    log_file = "/tmp/log/processor.log"
    logger = None
    subject_prefix = "BASE"                    # e.g. PDB-IHM or MA
    verbose = True
    notify = True
    domain_sname = "PDB"
    entry_rcb = None                           # user structure

    def __init__(self, catalog=None, store=None, deriva_host=None, catalog_id=None, credential_file=None,
                 scratch_dir=None, cfg=None, logger=None, log_level="info", log_file="/tmp/log/processor.log", verbose=None,
                 email_config_file=None, cutoff_time_pacific=None, release_time_utc=None
                 ):
        
        if scratch_dir: self.scratch_dir = scratch_dir
        os.system(f'mkdir -p {self.scratch_dir}')
        self.cfg = cfg
        if verbose: self.verbose = verbose
        if self.cfg.is_dev:
            log_file = "%s_dev.log" % (log_file.rsplit(".log", 1)[0])
        self.logger = logger if logger else init_logger(log_level, log_file)
        
        # -- ermrest and hatrac        
        self.catalog = catalog
        if not self.catalog:
            self.deriva_host = deriva_host
            self.credential_file = credential_file
            self.catalog_id = catalog_id
            credentials = get_credential(self.deriva_host, self.credential_file)
            if not credentials:
                raise Exception("ERROR: a proper credential or credential file is required. Provided credential_file: %s" % (credential_file))
            server = DerivaServer('https', self.deriva_host, credentials)
            self.catalog = server.connect_ermrest(self.catalog_id)
        self.catalog.dcctx['cid'] = 'pipeline'
        self.store = store
        if not self.store:
            self.store = HatracStore('https', self.deriva_host, credentials)
        
        # -- local host
        self.local_hostname = socket.gethostname() # processing host

        # -- archive/release time
        self.cutoff_time_pacific = cutoff_time_pacific
        self.release_time_pacific = release_time_utc

        # -- email
        email_config_file = email_config_file
        if not email_config_file: raise Exception("ERROR: Email configuration is required")
        with open(email_config_file, "r") as f:
            self.email_config = json.load(f)
        if not self.email_config: raise Exception("ERROR: Proper email configuration in json format is required")

    # -------------------------------------------------------------------
    @classmethod
    def get_rcb_user(cls, catalog, sname, tname, rid):
        """ get RCB row from ERMrest_Client table
        """
        constraints="RID=%s/U:=(M:RCB)=(public:ERMrest_Client:ID)" % (rid)
        rows = get_ermrest_query(catalog, sname, tname, constraints=constraints)
        if len(rows) == 0:
            raise Exception("RID: %s doesn't exist in table %s:%s" % (rid, sname, tname))
        user = rows[0]
        user["Short_ID"] = user["ID"].rsplit("/")[1]
        return user
                    
    # -------------------------------------------------------------------
    def get_entry_rcb(self, entry_id):
        """ set up RCB user 
        """
        self.entry_rcb = self.get_rcb_user(self.catalog, self.domain_sname, "entry", entry_rid)
        
    # ------------------------------------------------------------------------
    def log_exception(self, e, notify=False, subject=None):
        """
        log exception, send email notificatioin if specified
        """
        #error_message = str(e)  = str(ev)
        et, ev, tb = sys.exc_info()
        tb_message = ''.join(traceback.format_exception(et, ev, tb))
        self.logger.error('!!! Got exception "%s: %s"\n' % (et.__name__, str(ev)))
        self.logger.error('%s' % (tb_message))
        if notify: self.send_mail(subject, tb_message)
        if self.verbose: print("tab_message ==> %s" % (tb_message))
        #return tb_message

    # -------------------------------------------------------------------        
    def get_archive_datetime(self, utz=False, isoformat=True):
        """
        Archive datetime is the upcoming Thursday 8 PM PT (or the value specified in the cutoff_time_pacific config parameter)
        """
        cutoff_time = time.strptime(self.cutoff_time_pacific, "%A %H:%M")
        now = dt.now(pytz.timezone("America/Los_Angeles"))
        now_to_cutoff_weekday = (cutoff_time.tm_wday - now.weekday()) % 7
        archive_datetime = now + timedelta(days=now_to_cutoff_weekday)
        #print("get_archive_datetime: weekday_diff = %s" % (now_to_cutoff_weekday))
        if now_to_cutoff_weekday == 0 and (now.hour > cutoff_time.tm_hour or (now.hour == cutoff_time.tm_hour and now.minute > cutoff_time.tm_min)):
            archive_datetime += timedelta(days=7)
        archive_datetime = archive_datetime.replace(hour=cutoff_time.tm_hour,minute=cutoff_time.tm_min,second=0,microsecond=0)
        #print("archive pacific time: %s" % (str(archive_datetime)))
        if utz: 
            archive_datetime = archive_datetime.astimezone(timezone.utc)
        print("archive returned time (utc=%s): %s " % (str(utz), str(archive_datetime)))
        if isoformat:
            return str(archive_datetime)
        else: 
            return archive_datetime
        
    # -------------------------------------------------------------------
    def get_release_datetime_utc(self, isoformat=True):
        """
        Release Date logic:
          - If the REL is set before the archive deadline reference time (Thursday 11 PM PT), the release date is next Wednesday 0 UTC.
          - If REL is set after the archive deadline, the release date is the Wednesday after the next 0 UTC.
        Caveat: Cutoff datetime and archive datetime are in Pacific time and release date is always Wednesday 0:00 UTC.
          Because of the time zone difference, any cutoff time between Tuesday 16:00 PT and Wednesday 00:00 PT will result in a wrong release date
          (release date before cutoff datetime). Do not set cutoff datetime between Tuesday 16:00 PT and Wednesday 00:00 PT.
        TODO: Add validation to throw an error when the cutoff-time is not compatible with release time
        """
        archive_datetime = dt.fromisoformat(self.get_archive_datetime(isoformat=True))
        release_time = time.strptime(self.release_time_utc, "%A %H:%M")
        diff_weekday = (release_time.tm_wday - archive_datetime.weekday()) % 7
        if diff_weekday == 0:
            release_datetime = archive_datetime + timedelta(days=7)
        else: 
            release_datetime = archive_datetime + timedelta(days=diff_weekday)
        release_datetime = release_datetime.replace(hour=release_time.tm_hour,minute=release_time.tm_min,second=0,microsecond=0)
        print("release time (utc): %s (diff = %d, %s)" % (str(release_datetime), diff_weekday, release_time.tm_hour))
        if isoformat:
            return str(release_datetime)
        else: 
            return release_datetime

    # -------------------------------------------------------------------
    def sendLinuxMail(self, subject, text, receivers):
        """
        Send Linux email notification
        """
        if receivers == None:
            receivers = self.email_config['receivers']
        temp_name = '/tmp/{}.txt'.format(next(tempfile._get_candidate_names()))
        fw = open(temp_name, 'w')
        fw.write('{}\n\n{}'.format(text, self.email_config['footer']))
        fw.close()
        fr = open(temp_name, 'r')
        args = ['/usr/bin/mail', '-r', self.email_config['sender'], '-s', 'DEV {}'.format(subject), receivers]
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=fr)
        stdoutdata, stderrdata = p.communicate()
        returncode = p.returncode
        
        if returncode != 0:
            self.logger.debug('Can not send Linux email for file {}.\nstdoutdata: {}\nstderrdata: {}\n'.format(temp_name, stdoutdata, stderrdata)) 
        else:
            self.logger.debug('Sent Linux email for file {}.\n'.format(temp_name)) 
        
        fr.close()
        os.remove(temp_name)

    # -------------------------------------------------------------------
    """
    # HT TODO: make this not deployment specific
    json structure in mail.json:
    """
    def send_mail(self, subject, text, receivers=None):
        """
        Send email notification
        """
        if not self.notify:
            if self.verbose: print("Send mail: subject: %s, text:%s" % (subject, text))
            return
        if self.email_config['server'] and self.email_config['sender'] and (self.email_config['receivers'] or self.email_config['curators']):
            if self.subject_prefix:
                subject = '%s %s' % (self.subject_prefix, subject)
            if not self.cfg.is_prod:
                subject = "DEV:%s %s" % (self.catalog_id, subject)
            text = "Processing hostname: %s, catalog_id: %s\n\n" % (self.local_hostname, self.catalog_id, text)
            if not receivers: receivers = self.email_config['receivers']
            retry = 0
            ready = False
            while not ready:
                try:
                    msg = MIMEText('%s\n\n%s' % (text, self.email_config['footer']), 'plain')
                    msg['Subject'] = subject
                    msg['From'] = self.email_config['sender']
                    msg['To'] = receivers
                    s = smtplib.SMTP_SSL(self.email_config['server'], self.email_config['port'])
                    s.login(self.email_config['user'], self.email_config['password'])
                    s.sendmail(self.email_config['sender'], receivers.split(','), msg.as_string())
                    s.quit()
                    self.logger.debug(f'Sent email notification to {receivers}.')
                    ready = True
                except socket.gaierror as e:
                    if e.errno == socket.EAI_AGAIN:
                        time.sleep(100)
                        retry = retry + 1
                        ready = retry > 10
                    else:
                        ready = True
                    if ready:
                        self.log_exception(e)
                except:
                    self.log_exception(e)
                    ready = True


# -------------------------------------------------------------------                    
def test_exception():
    try:
        raise ErmrestError("ERROR: Something is wrong")
    except Exception as e:
        error_message = str(e)
        et, ev, tb = sys.exc_info()
        tb_message = error_message + '\n' + ''.join(traceback.format_exception(et, ev, tb))
        print("error_message: %s" % (error_message))
        print("name: %s, ev: %s\n" % (et.__name__, str(ev)))
        print("tb_message: %s" % (tb_message))
        

# -- =================================================================================
def main(server_name, catalog_id, credentials, args):
    server = DerivaServer('https', server_name, credentials)
    store = HatracStore('https', server_name, credentials)
    catalog = server.connect_ermrest(catalog_id)
    model = catalog.getCatalogModel()

    set_logger()
    
    cutoff_time = args.cutoff_time if args.cutoff_time else None
    processor = PipelineProcessor(
        hostname=args.host, credential_file=args.credential_file, catalog_id=args.catalog_id, cutoff_time_pacific=cutoff_time,
        logger=logger, email_config="/home/hongsuda/.secrets/mail.json", cfg=cfg
    )
    
    if False : #test_release_date:
        processor.get_archive_datetime(utz=True)
        release_date = processor.get_release_datetime_utc(isoformat=False).strftime("%Y-%m-%d")
        print("release_date: %s" % (release_date))

    processor.send_mail("Test_email", "test send_email utility", receivers=["hongsuda@isi.edu"])
    
    '''# test exception
    try:
        raise ErmrestError("ERROR: Something is wrong")
        #shared.test_logging(logger) # -- test logging from a different file
    except Exception as e:
        print("----------------")        
        processor.log_exception(e)
        print("----------------")
    '''
 # -- =================================================================================
if __name__ == '__main__':
    cli = ConfigCLI("extras", None, 1)
    cli.parser.add_argument('--cutoff-time', metavar='<cutoff_time>', help="cutoff_time in PT", required=False)
    cli.parser.add_argument('--catalog-id', metavar='<catalog_id>', help="catalog id (default 99)", default="99", required=False)    
    args = cli.parse_cli()
    credentials = get_credential(args.host, args.credential_file)
    
    main(args.host, args.catalog_id, credentials, args)
                    
