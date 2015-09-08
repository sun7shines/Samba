# -*- coding: utf-8 -*-

import syslog 
import traceback
import socket
import os.path

import optevent_db_op

import system.network.dns_service_op
import operation.vhost.domain_db
import operation.vhost.smbqa_db

import support.uuid_op
import time

SMB_CONF_FILE = '/etc/samba/smb.conf'

def get_krb5_strs(domain_name,domain_ip):
    
    u_domain_name = domain_name.upper()
    return '''[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log
[libdefaults]
 default_realm = %s
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24000
    
[realms]
 %s = {
  kdc = %s:88
  default_domain = %s
 }
    
[domain_realm]
 .%s = %s
 %s = %s
    
[kdc]
 profile = /var/kerberos/krb5kdc/kdc.conf
[appdefaults]
 pam = {
  debug = false
  ticket_lifetime = 36000
  renew_lifetime = 36000
  forwardable = true
  krb4_convert = false
 }
 '''%(u_domain_name,u_domain_name,domain_ip,u_domain_name,domain_name,u_domain_name,domain_name,u_domain_name)
 
def modify_krb5(domain_name,domain_ip):
    
    #ad_name = 'minkey.com'
    try:
        krb5_strs = [get_krb5_strs(domain_name,domain_ip)]
        
        file_name = "/etc/krb5.conf"
        f = open(file_name,'w')
        f.writelines(krb5_strs)
        f.close()
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'modify_krb5: '+str(traceback.format_exc()))
        return False,'modify krb5 conf file failed'
    
def save_user_dns():
    
    dns_user = '/etc/resolv.conf_user'
    file_name = '/etc/resolv.conf'
    cmd = 'rm -f %s' % (dns_user)
    os.system(cmd)
    cmd = 'cp %s %s' % (file_name,dns_user)
    os.system(cmd)
    
def recover_user_dns():
    
    file_name = '/etc/resolv.conf'
    dns_user = '/etc/resolv.conf_user'
    cmd = 'rm -f %s' % (file_name)
    os.system(cmd)
    cmd = 'cp %s %s' % (dns_user,file_name)
    os.system(cmd)
                
def modify_dns(domain_ip):
    # 只能有一个dns，且为域控服务器
    dns_str = 'nameserver %s' % domain_ip
    file_name = '/etc/resolv.conf'
    try:
        lines = [dns_str]
        f = open(file_name,'w')
        f.writelines(lines)
        f.close()
    except:
        syslog.syslog(syslog.LOG_ERR,'modify_dns: '+str(traceback.format_exc()))
        return False,'modify resolv.conf failed'
    return True,''

def modify_nss():
    
    file_name = '/etc/nsswitch.conf'
    try:
        f = open(file_name)
        lines = f.readlines()
        f.close()
        line_num = 0
        for line in lines:
            if line.strip().startswith('#'):
                line_num = line_num+1
                continue
            if line.strip().find('passwd') != -1:
                if line.strip().find('winbind') == -1:
                    lines[line_num] = 'passwd:     files winbind\n'
            if line.strip().find('shadow') != -1:
                if line.strip().find('winbind') == -1:
                    lines[line_num] = 'shadow:     files winbind\n'
            if line.strip().find('group') != -1:
                if line.strip().find('winbind') == -1:
                    lines[line_num] = 'group:      files winbind\n'
            line_num = line_num+1
            
        f = open(file_name,'w')
        f.writelines(lines)
        f.close()              
    except:
        syslog.syslog(syslog.LOG_ERR,'modify_nss: '+str(traceback.format_exc()))
        return False,'modify nsswitch.conf failed'        
    return True,''

def modify_lmhosts(domain_name, vs_ip):
    
    file_name = '/etc/samba/lmhosts'
    #vs_ip = system.network.dns_service_op.get_localhost_ip()
    if not vs_ip:
        return False,'get host ip failed'
    hostname = socket.gethostname()
    lm_str = '%s %s.%s\n' %(vs_ip,hostname,domain_name)
    
    lines = [lm_str]
    try:
        f = open(file_name,'w')
        f.writelines(lines)
        f.close()
    except:
        syslog.syslog(syslog.LOG_ERR,'modify_lmhosts: '+str(traceback.format_exc()))
        return False,'modify samba lmhosts failed'               
    return True,''

def get_usrs_gloab_strs():
    
    return '''[global]
        server string = File Share
        log file = /var/log/samba/log.%m
        max log size = 50
        security = user
        passdb backend = smbpasswd
        cups options = raw       
        load printers = no
        printing = bsd
        printcap name = /dev/null
        disable spoolss = yes
        

'''
    
def get_user_home_strs():
    
    return '''[homes]
        comment = Home Directories
        browseable = no
        writable = yes

[printers]
        comment = All Printers
        path = /var/spool/samba
        browseable = no
        guest ok = no
        writable = no
        printable = yes

'''
    
def get_ads_global_strs(domain_name,storage_path):
    
    u_domain_name = domain_name.upper()
    workgroup = u_domain_name.split('.')[0]
    return '''[global]
        workgroup = %s
        server string = Filesrv
        password server = %s
        realm = %s
        security = ads
        idmap uid = 16777216-33554431
        idmap gid = 16777216-33554431
        template shell = /sbin/nologin

        winbind use default domain = true
        winbind offline logon = true
        template home dir = %s/'''% (workgroup,u_domain_name,u_domain_name,storage_path) +'''%U
        winbind separator = /

        winbind enum groups = yes
        winbind enum users = yes

''' 
    
def get_ads_home_strs(storage_path,domain_name):
    
    ads_storage_path = ''
    if storage_path == '/home':
        ads_storage_path = ''
    else:
        ads_storage_path = storage_path
        
   
    return '''
[homes]
        comment = Home Directories
        path = %s/''' % storage_path +'''.vmshare/domain/%s''' % (('_').join(domain_name.split('.'))) + '''_%U
        read only = No
        browseable = No
        root preexec = /usr/bin/python /usr/vmd/operation/vhost/mkhome.pyc %U %G''' + ''' '%s'
        
''' % ads_storage_path

def modify_smb_to_ads(domain_name,storage_path):
    
    try:    
        ads_global_strs = get_ads_global_strs(domain_name,storage_path)
        flag,local_share_strs = operation.vhost.smbqa_db.get_local_share_strs_by_db()
        if not flag:
            return False,local_share_strs
        ads_home_strs = get_ads_home_strs(storage_path,domain_name)
        
        lines = [ads_global_strs+local_share_strs+ads_home_strs]
        f = open(SMB_CONF_FILE,'w')
        f.writelines(lines)
        f.close()
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'modify_smb_to_ads: '+str(traceback.format_exc()))
        return False,'modify smb.conf to ads type failed'
    
def update_samba_conf_ads(fn_path,share_path,admin_name,user_name):
    
    domain_info = operation.vhost.domain_db.get_domain_info()
    if not domain_info:
        return False,'host does not has domain info'
    domain_name = domain_info['domainname']
    storage_path = domain_info.get('storagepath')
    
    strx = '''    
        
        [%s]
        comment = This is a directory of TS.
        path = %s
        public = no
        admin users = %s
        valid users = %s
        writable = yes
        write list = +staff

''' % (share_path,fn_path,admin_name,user_name)

    try:
        ads_global_strs = get_ads_global_strs(domain_name,storage_path)
        
        flag,oldlocalstrs = operation.vhost.smbqa_db.get_local_share_strs_by_db()
        if not flag:
            return False,oldlocalstrs
        
        localstrs = oldlocalstrs+strx
        
        ads_home_strs = get_ads_home_strs(storage_path,domain_name)
        
        lines = [ads_global_strs+localstrs+ads_home_strs]
        f = open(SMB_CONF_FILE,'w')
        f.writelines(lines)
        f.close()
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'update_samba_conf_ads: '+user_name+' '+str(traceback.format_exc()))
        return False,'update samba config file failed'
    
def modify_smb_to_user():
    
    try:
        user_global_strs = get_usrs_gloab_strs()
        flag,local_share_strs = operation.vhost.smbqa_db.get_local_share_strs_by_db()
        if not flag:
            return False,local_share_strs
        user_home_strs = get_user_home_strs()
        
        lines = [user_global_strs+user_home_strs+local_share_strs]
        f = open(SMB_CONF_FILE,'w')
        f.writelines(lines)
        f.close()
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'modify_smb_to_user: '+str(traceback.format_exc()))
        return False,'modify smb.conf to user type failed'       

def init_quota_default():
    
    try:
        file_name = '/etc/samba/quota_default.conf'
        if not os.path.exists(file_name):
            lines = ['1000000 1000000'+'\n']
            f = open(file_name,'w')
            f.writelines(lines)
            f.close()
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'init_quota_default: '+str(traceback.format_exc()))
        return False,'init quota default conf failed'

def execute_cmds(domain_name,domain_ip,admin_name,password):
    
    u_domain_name = domain_name.upper()

    cmd = "(echo '%s';) | kinit %s@%s > /dev/null" % (password,admin_name,u_domain_name)
    if 0 != os.system(cmd):
        return False,'kinit password error or Clock skew too great while getting initial credentials'
    time.sleep(1)
    
    cmd = 'chkconfig smb on > /dev/null'
    if 0 != os.system(cmd):
        return False,'chkconfig smb error'    
    time.sleep(1)
    
    cmd = 'chkconfig nmb on > /dev/null'
    if 0 != os.system(cmd):
        return False,'chkconfig nmb error'    
    time.sleep(1)
    
    cmd = 'chkconfig winbind on > /dev/null'
    if 0 != os.system(cmd):
        return False,'chkconfig winbind error'    
    time.sleep(1)
    
    cmd = '/etc/init.d/smb restart'
    if 0 != os.system(cmd):
        return False,'restart service smb error'     
    time.sleep(2)
    
    cmd = '/etc/init.d/nmb restart'
    if 0 != os.system(cmd):
        return False,'restart service nmb error'     
    time.sleep(2)
    
    cmd = 'net ads leave -U %s@%s' % (admin_name,domain_name) +'%'+'%s' % password  
    os.system(cmd)
    time.sleep(1)
        
    cmd = 'net ads join -U %s@%s' % (admin_name,domain_name) +'%'+'%s > /dev/null' % password
    if 0 != os.system(cmd):
        return False,'host join domain failed'
    time.sleep(3)
    
    cmd = '/etc/init.d/winbind restart > /dev/null'
    if 0 != os.system(cmd):
        return False,'restart service winbind failed'
    time.sleep(3)
    
    cmd = 'wbinfo -u > /dev/null'
    if 0 != os.system(cmd):
        return False,'excute command wbinfo error'
    
    return True,''

def excute_samba_cmds():
    
    cmd = '/etc/init.d/smb restart'
    if 0 != os.system(cmd):
        return False,'restart service smb error'     
    time.sleep(2)
    
    cmd = '/etc/init.d/nmb restart'
    if 0 != os.system(cmd):
        return False,'restart service nmb error'
    time.sleep(2)
        
    cmd = '/etc/init.d/winbind restart > /dev/null'
    if 0 != os.system(cmd):
        return False,'restart service winbind failed'
    
    return True,''
def join_domain_op(event):
    
    domain_name = event.param['domain_name']
    domain_ip = event.param['domain_ip']
    admin_name = event.param['admin_name']
    password = event.param['password']
    
    domain_info = operation.vhost.domain_db.get_domain_info()
    if domain_info:
        return False,'host has domain info'
    
    flag,msg = modify_krb5(domain_name,domain_ip)
    if not flag:
        return False,msg
    
    save_user_dns()
    flag,msg = modify_dns(domain_ip)
    if not flag:
        return False,msg
    
    flag,msg = modify_nss()
    if not flag:
        return False,msg
    
    flag,msg = modify_smb_to_ads(domain_name,'/home')
    if not flag:
        return False,msg
    
    flag,msg = modify_lmhosts(domain_name, domain_ip)
    if not flag:
        return False,msg
    
    flag,msg = init_quota_default()
    if not flag:
        return False,msg
    
    flag,msg = execute_cmds(domain_name,domain_ip,admin_name,password)
    if not flag:
        return False,msg
    
    vsuuid = support.uuid_op.get_vs_uuid()[1]
    storage_path = None
    flag,msg = operation.vhost.domain_db.insert_domain_info(domain_name,domain_ip,admin_name,password,storage_path,vsuuid)
    if not flag:
        return False,msg
    operation.vhost.smbqa_db.smbpasswd_users('/etc/samba/users.ads')
    return True,''

def join_domain(event):

    eventexestat = "successed"
    flag,message=join_domain_op(event)
    if not flag:
        modify_smb_to_user()
        recover_user_dns()
        excute_samba_cmds()
        vsuuid = support.uuid_op.get_vs_uuid()[1]
        operation.vhost.domain_db.delete_domain_info(vsuuid)
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def quit_domain_op(event):
    
    domain_name = event.param['domain_name']
    domain_name = domain_name.upper()
    admin_name = event.param['admin_name']
    password = event.param['password']
    force_quit = event.param['force_quit']
    
    domain_info = operation.vhost.domain_db.get_domain_info()
    if not domain_info:
        return False,'host has no domain info'
    
    if force_quit == "no":
        cmd = 'net ads leave -U %s@%s' % (admin_name,domain_name) +'%'+'%s' % password  
        syslog.syslog(syslog.LOG_ERR,'host quit domain: '+cmd)
        if 0 != os.system(cmd):
            return False,'host leave domain failed,may wrong password'
    
    recover_user_dns()
    flag,msg = modify_smb_to_user()
    if not flag:
        return False,msg
    # execute_cmds
    flag,msg = excute_samba_cmds()
    if not flag:
        return False,msg

    ads_path = '%s/.vmshare/domain' % (domain_info['storagepath'])
    cmd = "find %s -name '.entry_path' | xargs rm -f " % (ads_path)
    os.system(cmd)
         
    vsuuid = support.uuid_op.get_vs_uuid()[1]
    flag,msg = operation.vhost.domain_db.delete_domain_info(vsuuid)
    if not flag:
        return False,msg
    operation.vhost.smbqa_db.smbpasswd_users('/etc/samba/users.user')
    
    return True,''

def quit_domain(event):

    eventexestat = "successed"
    flag,message=quit_domain_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def set_domain_st_op(event):
    
    storage_path = event.param['storage_path']
    domain_info = operation.vhost.domain_db.get_domain_info()
    if not domain_info:
        return False,'host does not has domain info'
    domain_name = domain_info['domainname']
    domain_ip = domain_info['domainip']
    admin_name = domain_info['adminname']
    password = domain_info['password']
    
    flag,msg = modify_smb_to_ads(domain_name,storage_path)
    if not flag:
        return False,msg
    
    flag,msg = execute_cmds(domain_name,domain_ip,admin_name,password)
    if not flag:
        return False,msg
    
    vsuuid = support.uuid_op.get_vs_uuid()[1]
    flag,msg = operation.vhost.domain_db.update_domain_storage(storage_path,vsuuid)
    if not flag:
        return False,msg
    return True,''

def set_domain_st(event):

    eventexestat = "successed"
    flag,message=set_domain_st_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def set_ad_quota_default_op(event):
    
    quota_size = event.param['quota_size']
    file_name = '/etc/samba/quota_default.conf'
    try:
        lines = ['%s %s\n' % (str(int(float(quota_size))),str(int(float(quota_size))))]
        f = open(file_name,'w')
        f.writelines(lines)
        f.close()
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'set_ad_quota_default_op: '+str(traceback.format_exc()))
        return False,'set domain quota default size failed'

def set_ad_quota_default(event):

    eventexestat = "successed"
    flag,message=set_ad_quota_default_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def set_user_quota(quota_size,smb_user):
    
    try:
        file_name = '/etc/samba/quota_user.conf'
        lines = ['%s %s\n' % (str(int(float(quota_size))),str(int(float(quota_size))))]
        f = open(file_name,'w')
        f.writelines(lines)
        f.close()
        
        src = '/etc/samba/quota_user.conf'
        dest = '/root/quota.conf'
        
        cmd = 'rm -f %s' % dest
        os.system(cmd)
        
        cmd = 'cp %s %s' % (src,dest)
        os.system(cmd)
        
        cmd = 'edquota -u %s' % smb_user
        os.system(cmd) 
        
        cmd = 'rm -f %s' % dest
        os.system(cmd)
        
    except:
        syslog.syslog(syslog.LOG_ERR,'set_ad_quota_user_op: '+str(traceback.format_exc()))
        return False,'set domain quota user failed'
        
    return True,''

def set_ad_quota_user_op(event):
    
    quota_size = event.param['quota_size']
    smb_user = event.param['smb_user']
    
    flag,msg = set_user_quota(quota_size,smb_user)
    if not flag:
        return False,msg
    
    # update database
    vsuuid = support.uuid_op.get_vs_uuid()[1]
    #quota_size = int(quota_size)/1024
    flag,msg = operation.vhost.domain_db.update_domain_user_info(smb_user,quota_size,vsuuid)
    if not flag:
        return False,msg
    return True,''

def set_ad_quota_user(event):

    eventexestat = "successed"
    flag,message=set_ad_quota_user_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")
