#!/usr/bin/env python
__author__ = 'Nguyen Duc Trung Dung'
__email__ = 'ndtdung@spsvietnam.vn'
__license__ = 'GPL'
__version__ = '2.0'

import ConfigParser
import time
import datetime
import os
import optparse
import re
import shutil
import sys
import commands
from pygtail import Pygtail
run = commands.getstatusoutput


#READ CONFIG
def configuration(filename):
    log_prefix = {'%a' : 'app_name',
                  '%u' : 'user_name',
                  '%d' : 'database_name',
                  '%r' : 'remote_host_port',
                  '%h' : 'remote_host',
                  '%p' : 'pid',
                  '%t' : 'timestamp_wo_ms',
                  '%m' : 'timestamp_ms',
                  '%i' : 'command_tag',
                  '%e' : 'sql_state',
                  '%c' : 'session_id',
                  '%l' : 'session_line_number',
                  '%s' : 'session_start_timestamp',
                  '%v' : 'virtual_transaction_id',
                  '%x' : 'transaction_id',  # 0 if none
                  '%q' : 'stop_here',  # in non-session processes
                  '%%' : '%'}
    config = ConfigParser.RawConfigParser()
    config.read(filenames=filename)
    # log section
    line_prefix = config.get('log', 'line.prefix').split('|')
    log_directory = config.get('log', 'log.directory').split('|')
    file_name = config.get('log', 'file.name').split('|')
    event_file = config.get('log', 'event.file').split('|')
    # censored section
    censored = config.get('censored', 'censored').split('|')
    # filter section
    user_filter = config.get('filter', 'user.filter').split('|')
    user_exclusive = config.get('filter', 'user.exclusive').split('|')
    db_filter = config.get('filter', 'db.filter').split('|')
    db_exclusive = config.get('filter', 'db.exclusive').split('|')
    ip_filter = config.get('filter', 'ip.filter').split('|')
    ip_exclusive = config.get('filter', 'ip.exclusive').split('|')
    command_filter = config.get('filter', 'command.filter').split('|')
    command_exclusive = config.get('filter', 'command.exclusive').split('|')
    # mail section
    mail_time = config.get('mail', 'mail.time')
    mail_subject = config.get('mail', 'mail.subject')
    mail_to = config.get('mail', 'mail.to')
    mail_content = config.get('mail', 'mail.content')
    macro = []
    for m in range(1, 11):
        txt = 'macro%d' % m
        macro.append(config.get('mail', txt))
    return


def config_reader(config_file):
    f = open(config_file, 'r')
    config_options = f.read().split('\n')
    f.close()
    config_options = [x for x in config_options if not re.match(r'^#', x)]  # remove comment lines
    for option in config_options:
        if re.match('CENSORED=', option):
            censored_list = option.split('=')[1]
        elif re.match(r'^USER_FILTER=', re.IGNORECASE):
        elif re.match(r'^USER_EXCLUSIVE=', re.IGNORECASE):
        elif re.match(r'^COMMAND=', re.IGNORECASE):
        elif re.match(r'DB_EXCLUSIVE=', re.IGNORECASE):
        elif re.match(r'IP_EXCLUSIVE=', re.IGNORECASE):
        else:
            pass
    usr_ls = ''
    usr_ig_ls = ''
    usr_cmd = ''
    db_ls = ''
    ip_ls = ''
    for conf in config_options:
        if not comment.search(conf) and neu_char in conf:
            neutralize.append(conf)
        elif usr.search(conf):
            usr_ls = conf.split('=')[1].split(';')
        elif cmds.search(conf):
            usr_cmd = '|'.join(conf.split('=')[1].split(';'))
        elif usr_exclusive.search(conf):
            usr_ig_ls = conf.split('=')[1].split(';')
        elif db.search(conf):
            db_ls = conf.split('=')[1].split(';')
        elif ip.search(conf):
            ip_ls = conf.split('=')[1].split(';')
    if len(neutralize) > 0:
        for i in range(0, len(neutralize)):
            neutralize[i] = neutralize[i].split(neu_char)
        return neutralize, usr_ls, usr_cmd, usr_ig_ls, db_ls, ip_ls
    else:
        print 'WARNING: No rule found!'
        sys.exit(1)
        

def file_identify(absolute_path):  # identify log file format: postgresql-2013-12-12_000000.log
    fle_date = datetime.datetime.now().strftime('%Y-%m-%d')
    fle_prefix = 'postgresql-' + fle_date + '_'
    fle_list = [x for x in os.listdir(absolute_path) if fle_prefix in x]
    for x in range(0, 30):
        try:
            _ = [int(fle.split('.')[0].split('_')[-1]) for fle in fle_list if fle != '']
        except Exception:
            time.sleep(1)
        else:
            break
    try:
        fle_order = '%06d' % max(_)
    except Exception as _:
        time.sleep(10)
        fle_order = '000000'
    else:
        pass
    abs_fle_name = absolute_path + fle_prefix + fle_order + '.log'
    return abs_fle_name


def clear_offset():
    print 'INFO - Time to clear Offset files'
    offset = opts.directory + 'postgresql-' + (datetime.datetime.now() - datetime.timedelta(hours=1)).strftime('%Y-%m-%d') + '*.offset'
    _, out = run('rm %s' % offset)
    if _ != 0:
        print 'ERROR - Unable to clear offset files:', out
    else:
        print 'INFO - Offset files cleared!'


class TAIL:
    def __init__(self, path, rules, out_screen, send_mail_time, event_file, config):
        self.path = path
        self.fp = None
        self.last_size = 0
        self.last_ino = -1
        self.rules = rules  # neutralize, usr_ls, usr_cmd, usr_exclusive_ls, db_ls, ip_ls
        self.out_screen = out_screen
        self.send_mail_time = send_mail_time
        self.event_file = event_file
        self.config = config

    def process(self, fle_name):
        #  open file if it's not already open
        if not self.fp:
            try:
                self.fp = open(fle_name, 'r')
                stat = os.stat(fle_name)
                self.last_ino = stat[1]
                self.last_size = 0
            except IOError:
                if self.fp:
                    self.fp.close()
                self.fp = None
        if not self.fp:
            return
        #  check to see if file has moved under us
        try:
            stat = os.stat(fle_name)
            this_size = stat[6]
            this_ino = stat[1]
            if this_size < self.last_size or this_ino != self.last_ino:
                raise Exception
        except Exception:
            self.fp.close()
            self.fp = None
            return
        #read if size has changed
        if self.last_size < this_size:
            for line in Pygtail(fle_name):
                self.line_processing(line)
        self.last_size = this_size
        self.last_ino = this_ino

    def mailing(self):
        event_file = self.event_file + '_' + (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y%m%d')
        events = ''
        try:
            fle = open(event_file, 'r')
        except IOError as error:
            return 'LOG MISSED'
        else:
            events = fle.read()
            fle.close()
        if events == '' or events == ' ':
            mail_status = 'NO EVENT'
        else:
            fle = open(self.config, 'r')
            tmp = fle.read().split('\n')
            fle.close()
            mail_content = []
            mail_subject = '[You forgot SUBJECT]'
            mail_to = 'lxbinh@spsvietnam.vn'
            db_info = ''
            for t in tmp:
                if re.search(r'subject=', t, re.IGNORECASE):
                    mail_subject = t.split('=')[1]
                elif re.search(r'mail_to=', t, re.IGNORECASE):
                    mail_to = ' '.join(t.split('=')[1].split(';'))
                elif re.search(r'db_info=', t, re.IGNORECASE):
                    db_info = t.split('=')[1]
                elif not re.search('^#', t):
                    t = re.sub(r'\[db_info\]', db_info, t)
                    t = re.sub(r'\[event\]', events, t)
                    mail_content.append(t)
            #Create tmp mail content
            tmp_file = sys.argv[0] + '.tmp'
            fle = open(tmp_file, 'w')
            fle.write('\n'.join(mail_content))
            fle.close()
            cmd = 'mail -s "%s" %s < %s' % (mail_subject, mail_to, tmp_file)
            print '-' * 20
            print 'INFO - Time to send mail'
            _, output = run(cmd)
            if _ != 0:
                print 'ERROR - Unable to send mail. Reason: %s' % output
                print '-' * 20
                mail_status = 'ERROR'
                os.remove(tmp_file)
            else:
                print 'INFO - Mail sent with content: %s' % '\n'.join(mail_content)
                print '-' * 20
                mail_status = 'SENT'
                os.remove(tmp_file)
        return mail_status

    def line_processing(self, line):
        config = self.rules
        query = re.compile(r'%s' % config[2], re.IGNORECASE)
        tmp_fle = 'db_watcher.line'
        if line:
            #--check date header
            if len(line.split()) > 1 and line.split()[0] == datetime.datetime.now().strftime('%Y-%m-%d'):
                #--check db exclusive
                if len(line.split()) > 3 and any(db in line.split()[3] for db in config[4]):
                    #--check ip exclusive
                    if len(line.split()) > 4:
                        if any(ip in line for ip in config[5]):
                            if (not any(usr_exclusive in line.split()[4] for usr_exclusive in config[3]) and query.search(line))\
                                    or (any(usr in line.split()[4] for usr in config[1] if usr != '') and query.search(line)):
                                f = open(tmp_fle, 'w')
                                f.write('!@#$%^&*()')
                                f.close()
                            else:
                                if os.path.isfile(tmp_fle):
                                    os.remove(tmp_fle)
                                return
                        else:
                            return
                    else:
                        return
                else:
                    return
            else:
                if not (query.search(line) and os.path.isfile(tmp_fle)):
                    return
            #Neutralize output
            remain_part = line
            for neu in config[0]:
                fst = re.compile(r'%s' % neu[0], re.IGNORECASE)
                snd = neu[1]
                while len(remain_part) > len(neu[0]):
                    if fst.search(remain_part):
                        neu_part = fst.split(remain_part, 1)[1]
                        if neu_part:
                            neu_part = neu_part.split(snd, 1)[0].split()[0]
                            remain_part = line.split(neu_part)
                        if len(remain_part) > 0:
                            remain_part = remain_part[1]
                            line = line.replace(neu_part, '********')
                    else:
                        break
            if self.out_screen == 'ON':
                print line.replace('\n', '')
            else:
                if self.out_screen == 'OFF' and opts.event_file is not None:
                    f_out = open(self.event_file, 'a')
                    f_out.write(line)
                    f_out.close()

    def log_rotate(self):
        shutil.move(self.event_file, self.event_file + '_' + datetime.datetime.now().strftime('%Y%m%d'))
        open(self.event_file, 'a').close()

    def mainloop(self, sleep=1):
        mail_status = None
        init_date = datetime.datetime.now().date()
        while 1:
            current_log_file = self.file_identify(self.path)
            if datetime.datetime.now().time().strftime('%H:%M') == self.send_mail_time:
                if mail_status != 'SENT':
                    if mail_status == 'NO EVENT':
                        print 'INFO - No event log.'
                        print '-' * 20
                    if mail_status == 'LOG MISSED':
                        print 'WARNING - Log file missed!'
                        print '-' * 20
                    elif mail_status == 'ERROR':
                        print 'WARNING - Last sent error. Try again...'
                        print '-' * 20
                        mail_status = self.mailing()
                    else:
                        mail_status = self.mailing()
                else:
                    pass
            else:
                mail_status = None
            self.process(current_log_file)
            if datetime.datetime.now().date() != init_date:
                self.log_rotate()
                self.clear_offset()
                init_date = datetime.datetime.now().date()
            time.sleep(sleep)

# MAIN
if __name__ == "__main__":
    # get options
    op = optparse.OptionParser()
    op.add_option('-c', '--config', help='load config from file', dest='filename')
    op.add_option('-d', help='run in daemon mode', action='store_true', dest='daemon')
    opts, args = op.parse_args()
    if opts.filename is None:
        op.print_help()
        sys.exit(1)
    else:
        # read configuration file
        configuration(opts.filename)
        # start the job
        TAIL(opts.directory, rules, opts.daemon, opts.time, opts.log_file, opts.conf).mainloop()
