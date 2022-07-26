'''apport package hook for mysql-8.0

(c) 2009 Canonical Ltd.
Author: Mathias Gug <mathias.gug@canonical.com>
'''

from __future__ import print_function, unicode_literals
import os
import os.path

from apport.hookutils import (
    attach_conffiles,
    attach_file,
    attach_mac_events,
    path_to_key,
    read_file
    )

def _add_my_conf_files(report, filename):
    key = 'MySQLConf' + path_to_key(filename)
    report[key] = ""
    for line in read_file(filename).split('\n'):
        try:
            if 'password' in line.split('=')[0]:
                line = "%s = @@APPORTREPLACED@@" % (line.split('=')[0])
            report[key] += line + '\n'
        except IndexError:
            continue

def strip_protected(line):
    '''
    Mitigation for upstream bug that can lead to statements containing
    passwords being written to error log We strip out any lines containing
    terms listed on http://dev.mysql.com/doc/refman/8.0/en/password-logging.html
    (LP: #1574458)
    '''
    protected_terms = [
        'grant',
        'alter user',
        'create user',
        'set password',
        'create server',
        'alter server']
    for term in protected_terms:
        if term in line:
            return '--- Line containing protected term %s stripped from log ' \
                'by apport hook. Ref. Launchpad bug #1574458' % term
    return line

def add_info(report, ui=None):
    '''
    Collect system information relevant to mysql.
    '''
    attach_conffiles(report, 'mysql-server-8.0', conffiles=None)
    key = 'Logs' + path_to_key('/var/log/daemon.log')
    report[key] = ""
    for line in read_file('/var/log/daemon.log').split('\n'):
        try:
            if 'mysqld' in line.split()[4]:
                report[key] += line + '\n'
        except IndexError:
            continue
    if os.path.exists('/var/log/mysql/error.log'):
        key = 'Logs' + path_to_key('/var/log/mysql/error.log')
        report[key] = ""
        for line in read_file('/var/log/mysql/error.log').split('\n'):
            line = strip_protected(line)
            report[key] += line + '\n'
    attach_mac_events(report, '/usr/sbin/mysqld')
    attach_file(report, '/etc/apparmor.d/usr.sbin.mysqld')
    if not os.path.isdir('/etc/mysql'):
        report['EtcMysqlDirListing'] = str(False)
        response = ui.yesno("The /etc/mysql directory is missing, which "
                            "suggests a local configuration problem rather "
                            "than a bug in Ubuntu.  Do you still wish to "
                            "report this bug?")
        if not response: # user cancelled or answered No
            report['UnreportableReason'] = "Missing /etc/mysql directory"
            return False
    else:
        # By default my.cnf is a symlink, and _add_my_conf_files calls apport.hookutils.read_file()
        # doesn't support them, so send the link target separately instead. LP: #1969369
        if os.path.islink('/etc/mysql/my.cnf'):
            my_cnf_link = os.path.realpath('/etc/mysql/my.cnf')
            report['MySQLConf.etc.mysql.my.cnf'] = f'my.cnf links to {my_cnf_link}'
        else:
            _add_my_conf_files(report, '/etc/mysql/my.cnf')
        _add_my_conf_files(report, '/etc/mysql/mysql.cnf')
        for d in ['/etc/mysql/conf.d', '/etc/mysql/mysql.conf.d']:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    _add_my_conf_files(report, os.path.join(d, f))
    try:
        report['MySQLVarLibDirListing'] = str(os.listdir('/var/lib/mysql'))
    except OSError:
        report['MySQLVarLibDirListing'] = str(False)
    return True

if __name__ == '__main__':
    report = {}
    add_info(report)
    for key in report:
        print('%s: %s' % (key, report[key].split('\n', 1)[0]))
