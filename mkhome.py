# -*- coding: utf-8 -*-

import os
import random

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
sys.path.append("/usr/vmd")

import syslog
import traceback

import new_subthread
import global_params
global_params.django = True
sys.path.append("/usr/")
from django.conf import settings
sys.path.append("/usr/django_object")
try:
    import django_object.settings
    settings.configure(default_settings=django_object.settings)
except:
    pass

import operation.vhost.domain_db
import support.uuid_op
import operation.vhost.domain_op

import support.message.global_object
import support.message.vmd_message_queue
import dbmodule.db_module_interface



def get_available_port():
    
    cmd = "netstat -ntl |grep -v Active| grep -v Proto|awk '{print $4}'|awk -F: '{print $NF}'"
    procs = os.popen(cmd).read()
    procarr = procs.split("\n")
    tt= random.randint(32768, 61000)
    if tt not in procarr:
        return tt
    else:
        return get_available_port()


def __init_mkhome_server():
    """Init mkhome server ,recv mkhome db result."""
    
    try:
        support.message.global_object.MSG_MKHOME_OBJECT = support.message.vmd_message_queue.MKHOMEQueue()
    except:
        strs = str(traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, "Start mkhome server for mkhome failed: " + strs)
        return False
    return True

def _close_mkhome_server():
    
    try:
        support.message.global_object.MSG_MKHOME_OBJECT.server.close()
        #support.message.global_object.MSG_MKHOME_OBJECT.close()
        support.message.global_object.MSG_MKHOME_OBJECT = None
    except:
        strs = str(traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, "stop mkhome server for mkhome failed: " + strs)
        return False
    return True
    

def get_mkhome_db_message():
    """Get mkhome db  result message."""
    
    try:
        (flag, log_db_message) = \
         support.message.global_object.MSG_MKHOME_OBJECT.server.get()
    except support.message.message_queue.QueueGetError:
        return (False, "")
    try:
        support.message.global_object.MSG_MKHOME_OBJECT.server.put \
               ("recv successed")
    except support.message.message_queue.QueuePutError:
        return (False, "")
    return (flag, log_db_message)


def mkhome_server():
    """mkhome server to get mkhome db result."""
    
    while True:
        
        # e.g block here
        (flag, mkhome_db_message) = get_mkhome_db_message()
        if not flag:
            continue
        flag = dbmodule.db_module_interface.put_re_message_in_queue(mkhome_db_message)

def running_mkhome_server():
    """Running mkhome server,
    Get log mkhome  result message."""
    
    # e.g runing sub thread for dispatch
    desc = "start_mkhome_server"
    new_subthread.addtosubthread(desc, mkhome_server)
    return


def make_home(user,group,ads_storage_path):
    
    global_params.DB_PORT = support.message.global_object.MSG_MKHOME_SERVER_PORT
    if not ads_storage_path or not os.path.exists(ads_storage_path):
        return

    if user == 'admin':
        return
    if operation.vhost.domain_db.local_username(user):
        return
    domainobj = operation.vhost.domain_db.get_domain_info()
    if not domainobj:
        
        return 
    
    domain_name = domainobj['domainname']
    
    ads_home_path = '%s/.vmshare/domain/%s_%s' %(ads_storage_path,('_').join(domain_name.split('.')),user)
     
    if not os.path.exists(ads_home_path):
        cmd = 'mkdir -p %s' %(ads_home_path)
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        if not os.path.exists(ads_home_path):
            return
        
    entry_path = ads_home_path + '/' + '.entry_path'
    if not os.path.exists(entry_path):
        cmd = 'touch  %s' % entry_path
        os.system(cmd)
        
        cmd = 'chown %s %s' %(user,ads_home_path)
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        cmd = 'chgrp %s %s' %(group,ads_home_path)
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        cmd = 'chmod 700 %s' %(ads_home_path)
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        src = '/etc/samba/quota_default.conf'
        dest = '/root/quota.conf'
        
        cmd = 'rm -f %s' % dest
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        cmd = 'cp %s %s' % (src,dest)
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        cmd = 'edquota -u %s' %(user)
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
        
        cmd = 'rm -f %s' % dest
        os.system(cmd)
        syslog.syslog(syslog.LOG_ERR,'cmd: '+cmd)
    
    vsuuid = support.uuid_op.get_vs_uuid()[1] 
    userobj = operation.vhost.domain_db.get_domain_user_info(user, vsuuid)
    if not userobj:
        quota_size = operation.vhost.domain_db.get_quota_default_size()
        used_size = 0
        operation.vhost.domain_db.insert_domain_user_info(user,quota_size,used_size,vsuuid)
    else:
        quota_size = userobj.get('totalsize')
        operation.vhost.domain_op.set_user_quota(quota_size, user)
    
if __name__ == "__main__":

    user = sys.argv[1]
    group = sys.argv[2]
    ads_storage_path = sys.argv[4]
    global_params.init_threadlock()
    support.message.global_object.MSG_MKHOME_SERVER_PORT = get_available_port()
    global_params.DB_PORT = support.message.global_object.MSG_MKHOME_SERVER_PORT
    
    if not __init_mkhome_server():
        sys.exit(1)
    running_mkhome_server()
    try:
        make_home(user,group,ads_storage_path)
    except:
        syslog.syslog(syslog.LOG_ERR,'make home: '+str(traceback.format_exc()))
    finally:
        if not _close_mkhome_server():
            sys.exit(1)
