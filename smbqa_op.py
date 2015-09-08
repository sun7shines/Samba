# -*- coding: utf-8 -*-
import os
import sys
import time
import syslog
import traceback


import optevent_db_op
import support.uuid_op

import support.fileutil.file_option
import operation.vm.vmsys_op

import system.network.dns_service_op
import operation.vm.vmsys_interface
import operation.vhost.smbqa_db
import operation.vhost.domain_op
import operation.vstorage.storage_db_op
import operation.vm.vm_running_script

from support.fileutil.file_option import FileOption

import support.fileutil.directory_option

import dbmodule.db_module_interface
import support.lock_option
from dbmodule.db_op import *

SAMBA_CONF_FILE = '/etc/samba/smb.conf'
SPACE_SIZE_FILE = '/usr/vmd/.spacesize'

#对于非root用户，一律删掉该用户，同时保存用户的数据
def user_exists(user_name):
    #检查数据库
    return False

def user_move(user_name):
    #移动用户数据
    pass

def quota_init(storage_path):

    fngr = storage_path+'/'+'aquota.group'
    fnuser = storage_path+'/'+'aquota.user'

    if os.path.exists(fngr) and os.path.exists(fnuser):
        cmd = 'quotaoff -a'
        os.system(cmd)

        cmd = "quotacheck -mug "+storage_path
        os.system(cmd)

        cmd = 'quotaon -avug'
        os.system(cmd)
        return
    
    cmd = 'quotaoff -a'
    os.system(cmd)

    cmd = "quotacheck -cmug "+storage_path
    os.system(cmd)

    cmd = 'quotaon -avug'
    os.system(cmd)
    return

def sysuser_add(fn_path,user_name):

    smbqa_delete_act(fn_path,"no")

    cmd = "useradd -s /sbin/nologin -d "+fn_path+" "+user_name
    print cmd
    num = 0
    while num < 5:
        num = num + 1
        ret = os.system(cmd)
        if ret == 0:
            break
        time.sleep(1)

def quota_adduser(fn_path,user_name,softlimit,hardlimit):

    conf_path = "/root/quota.conf"
    cmd = "echo '" +str(int(float(softlimit)))+' '+str(int(float(hardlimit)))+"' > "+conf_path
    print cmd
    syslog.syslog(syslog.LOG_ERR,"quota: "+str(cmd))
    os.system(cmd)

    #cmd = "quotaoff -a"
    #syslog.syslog(syslog.LOG_ERR,"quota: "+str(cmd))
    #print cmd
    #os.system(cmd)

    cmd =  "edquota -u "+user_name
    syslog.syslog(syslog.LOG_ERR,"quota: "+str(cmd))
    print cmd
    os.system(cmd)

    #cmd =  "quotaon -avug"
    #syslog.syslog(syslog.LOG_ERR,"quota: "+str(cmd))
    #print cmd
    #os.system(cmd)

    cmd = "rm -f "+conf_path
    syslog.syslog(syslog.LOG_ERR,"quota: "+str(cmd))
    print cmd
    os.system(cmd)

    return True

def update_samba_conf(fn_path,share_path,admin_name,user_name):

    strx = '''        
    
        [%s]
        comment = This is a directory of TS.
        path = %s
        public = no
        admin users = %s
        valid users = %s
        writable = yes
        write list = +staff ''' % (share_path,fn_path,admin_name,user_name)

    support.lock_option.lock_acquire("smb_state_lock")
    try:
        newlines = []
        flag,local_share_strs = operation.vhost.smbqa_db.get_local_share_strs_by_db()
        if not flag:
            return False,local_share_strs
        
        user_global_strs = operation.vhost.domain_op.get_usrs_gloab_strs()
        user_home_strs = operation.vhost.domain_op.get_user_home_strs()
        
        newlines = [user_global_strs+user_home_strs+local_share_strs+strx]
        
        updated_file = support.fileutil.file_option.FileOption(SAMBA_CONF_FILE)
        updated_file.write_lines_file(newlines)
    finally:
        syslog.syslog(syslog.LOG_ERR,'update_samba_conf: '+user_name+' '+str(traceback.format_exc()))
        support.lock_option.lock_release("smb_state_lock")

    return True,''
                     
def samba_adduser(fn_path,share_path,admin_name,user_name,newpasswd,confirmpasswd,Restart="yes"):

    conf_type = operation.vhost.smbqa_db.get_smb_conf_type()
    if not conf_type:
        return False,'samba conf file type error'
    
    if conf_type == 'user':
        flag,msg = update_samba_conf(fn_path,share_path,admin_name,user_name)
        if not flag:
            return False,msg
        
    elif conf_type == 'ads':
        flag,msg = operation.vhost.domain_op.update_samba_conf_ads(fn_path,share_path,admin_name,user_name)
        if not flag:
            return False,msg
        
    cmd = "(echo '" + newpasswd + "';echo '" + confirmpasswd + "')|smbpasswd -as "+user_name
    os.system(cmd)
    operation.vhost.smbqa_db.write_user_list(user_name,newpasswd)
    
    if Restart == "yes":
        cmd = '/etc/init.d/smb restart'
        os.system(cmd)
    
        cmd = '/etc/init.d/nmb restart'
        os.system(cmd)

    return True,''

    #测试消息的返回“the username is in use”
def username_exists(user_name):

    #允许admin有多个共享路径
    if user_name == "admin":
        return False
    
    shareinfo = db_values('host_sharedir',{'username':user_name})
    if shareinfo:
        return True
    return False 

def get_all_host_shares(vc_ip=None):
    
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
    if vc_ip:
        module_object.ip_d = vc_ip
    module_object.message["field1"] = {}
    flag,msg = module_object.select()
    return (flag, msg)

def get_share_conflict_names(shareNames):
    
    conflictNames = []
    (flag, shareInfos) = get_all_host_shares()
    if not flag:
        return conflictNames, shareNames
    
    for x in shareInfos:
        if x["sharepath"].split("/")[-1] in shareNames:
            conflictNames.append(x["sharepath"].split("/")[-1])
            shareNames.remove(x["sharepath"].split("/")[-1])
    return conflictNames, shareNames

def get_shareinfo_by_vmuuid(vmuuid):

    shareinfos = {}
    hostuuid = support.uuid_op.get_vs_uuid()[1]
    #支持集群虚拟机配置cifs共享
    is_vcuuid,vcuuid,vc_ip = support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir",ip_d = vc_ip)
        module_object.message["field1"] = {"vmuuid":vmuuid}
        module_object.message["mt_attrname"] = "host__host_ip"
        flag,msg = module_object.get_with_mtinfo()
        if not flag:
            return {}
        
        shareinfos = msg["res"]
        shareinfos["ip"] = msg["mt_attr_value"]
    else:
        module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
        module_object.message["field1"] = {"vmuuid":vmuuid}
        flag,msg = module_object.select()
        if not flag:
            return {}
        shareinfos = msg[0]
    if shareinfos:
        return shareinfos
    else:
        return {}




def sharepath_exists(sharepath):

    
    shareinfo = db_values('host_sharedir',{'sharepath':sharepath})
    if shareinfo:
        return True
    return False

def add_shareinfo(parent_path,fn_path,admin_name,user_name,password,totalsize,vmuuid):
    
    hostuuid = support.uuid_op.get_vs_uuid()[1]
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
    field1 = {"host":{"db_name":"hosts","field":{"uuid":hostuuid}},
              "sharepath":fn_path,"parentpath":parent_path,"adminname":admin_name,"username":user_name,
              "password":password,"totalsize":float(totalsize),"vmuuid":vmuuid}
    module_object.message["field1"] = field1
    flag,msg = module_object.insert_f()
    if not flag:
        return False,'add share info failed'
    is_vcuuid,vcuuid,vc_ip = support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object.ip_d = vc_ip
        flag,msg = module_object.insert_f()
        if not flag:
            return False,'add share info failed'
    return True,""
    

def get_total_size(storage_path):

    (flag, fsinfo) = support.fileutil.directory_option.get_file_system_info(storage_path)
    if flag:
        total_size = float(fsinfo["total_size"])/1024
    else: 
        syslog.syslog(syslog.LOG_ERR,'get storage info failed ')
        return False,'get storage info failed',0
    total_size = total_size*1024*0.3
    syslog.syslog(syslog.LOG_ERR,'total_size '+str(total_size))
    return True,'',str(total_size)

def write_vmshare_size(storage_path,number):

    flag,message,total_size = get_total_size(storage_path) 
    if not flag:
        return False

    vm_share_size = float(total_size)/float(number)

    #个人用户最大空间限额为10G
    if vm_share_size> 10*1024*1024:
        vm_share_size = 10*1024*1024

    file_name = SPACE_SIZE_FILE
    FileOption(file_name).write_file(str(vm_share_size))

    return True

def get_space_size():

    file_name = SPACE_SIZE_FILE
    size = FileOption(file_name).read_file()[0].strip()
    return str(size)

def smbqa_init_op(event):
    syslog.syslog(syslog.LOG_ERR,'smbqa_init_op(event)_+_+_+_+_+_+__+_+_+_+_+_++_+_+_+_+')
    param = event.param
    storage_path = param.get('storage_path')
    share_path = param.get('share_path')
    user_name = param.get('user_name')
    password = param.get('password')
    number = param.get('number')
    space_size = '0' 

    fn_path = storage_path+'/.vmshare/'+share_path
    parent_path = None

    
    if not write_vmshare_size(storage_path,number):
        return False,'get vm share size false'

    if username_exists(user_name):
        #return False,'the username is in use'
        return True,'the basename is used again'

    if sharepath_exists(fn_path):
        return False,'the share path is in use'

    if not os.path.exists(storage_path):
        return False,'storage does not exists'

    if user_name != 'admin': 
        sysuser_add(fn_path,user_name)

    if not os.path.exists(fn_path):
        return False,'chmod share_path to 755 failed'

    cmd = 'chmod 755 '+fn_path
    os.system(cmd)
   
    flag,message = samba_adduser(fn_path,share_path,admin_name=user_name,user_name=user_name,newpasswd=password,confirmpasswd=password)
    if not flag:
        return flag,message
    vmuuid = None
    flag,message = add_shareinfo(parent_path,fn_path,user_name,user_name,password,space_size,vmuuid)
    return flag,message

def smbqa_conf_op(event):

    param = event.param
    parent_path = param.get('parent_path')
    share_path = param.get("share_path")
    admin_name = param.get('admin_name')
    user_name = param.get('user_name')
    password = param.get('password')
    vmuuid = param.get('vmuuid')

    space_size = get_space_size() 

    fn_path = parent_path+'/'+share_path

    if username_exists(user_name):
        return False,'the username is in use'
    
    if sharepath_exists(fn_path):
        return False,'the share path is in use'

    if not os.path.exists(parent_path):
        return False,'storage does not exists'

    if user_name != 'admin':
        sysuser_add(fn_path,user_name)

    quota_adduser(fn_path,user_name,softlimit=space_size,hardlimit=space_size)

    flag,message = samba_adduser(fn_path,share_path,admin_name,user_name,password,password)
    if not flag:
        return flag,message
    flag,message = add_shareinfo(parent_path,fn_path,admin_name,user_name,password,space_size,vmuuid) 
    return flag,message

def smbqa_update_op(event):
    
    param = event.param
    share_path = param.get('share_path')
    user_name = param.get('user_name')
    new_password = param.get('new_password')
    old_password = param.get('old_password')
    
    fmsg = ''
    vmuuid = None
    
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
    module_object.message["field1"] = {"sharepath":share_path,"username":user_name}
    flag,msg = module_object.select()
    if not flag or not msg:
        return False,'update samba password failed'
    if msg[0]['password'] != old_password:
        fmsg = 'gived wrong password and change to new password'
        
    vmuuid = msg[0]['vmuuid']
    
    module_object.message["field1"] = {"sharepath":share_path,"username":user_name}
    module_object.message["field2"] = {"password":new_password}
    flag,msg = module_object.modify()
    if not flag:
        syslog.syslog(syslog.LOG_ERR,'update samba password failed')
        return False,'update samba password failed'
        
    is_vcuuid,vcuuid,vc_ip = support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object.ip_d = vc_ip
        flag,msg = module_object.modify()
        if not flag:
            syslog.syslog(syslog.LOG_ERR,'update samba password failed')
    
    cmd = "(echo '" + new_password + "';echo '" + new_password + "')|smbpasswd -as "+user_name
    os.system(cmd)
    operation.vhost.smbqa_db.write_user_list(user_name,new_password)
    
    cmd = '/etc/init.d/smb restart'
    os.system(cmd)

    cmd = '/etc/init.d/nmb restart'
    os.system(cmd)
     
    if vmuuid:
        (flag, _) = operation.vm.vmsys_interface.tools_init_finished(vmuuid)
        if flag:
            try:
                send_message = {"tag":"net_delete_connection", "shareLst":[share_path.split("/")[-1], ]}
                output = operation.vm.vmsys_op.request_tools(vmuuid,send_message)
                if "successed" != output[0]:
                    syslog.syslog(syslog.LOG_ERR,'clear cifs dir failed: '+output[1])
                
                vs_ip = system.network.dns_service_op.get_localhost_ip()
                ips = system.network.dns_service_op.get_localhost_ips()
                path = share_path.split('/')[-1]
                send_message = {"tag":"net_add_connection","ip":vs_ip,"path":path,"username":user_name,"password":new_password, "ips":ips}
                output = operation.vm.vmsys_op.request_tools(vmuuid,send_message)
                if "successed" != output[0]:
                    syslog.syslog(syslog.LOG_ERR,'realloc cifs dir failed: '+output[1])
            except:
                syslog.syslog(syslog.LOG_ERR,"send msg to toos failed"+str(traceback.format_exc()))
        
    return True,fmsg

def delete_smconf(user_name):

    conf_type = operation.vhost.smbqa_db.get_smb_conf_type()
    if not conf_type:
        return False,'samba conf file type error'
    
    support.lock_option.lock_acquire("smb_state_lock")
    try:
        if conf_type == 'user':        
            newlines = []    
            flag,local_share_strs = operation.vhost.smbqa_db.get_local_share_strs_by_db(user_name)
            if not flag:
                return False,local_share_strs
            
            user_global_strs = operation.vhost.domain_op.get_usrs_gloab_strs()
            user_home_strs = operation.vhost.domain_op.get_user_home_strs()
            
            newlines = [user_global_strs+user_home_strs+local_share_strs]
            updated_file = support.fileutil.file_option.FileOption(SAMBA_CONF_FILE)
            updated_file.write_lines_file(newlines)
            
        elif conf_type == 'ads':
            
            domain_info = operation.vhost.domain_db.get_domain_info()
            if not domain_info:
                return False,'host does not has domain info'
            domain_name = domain_info['domainname']
            storage_path = domain_info['storagepath']
        
            ads_global_strs = operation.vhost.domain_op.get_ads_global_strs(domain_name,storage_path)
            
            flag,localstrs = operation.vhost.smbqa_db.get_local_share_strs_by_db(user_name)
            if not flag:
                return False,localstrs
            
            ads_home_strs = operation.vhost.domain_op.get_ads_home_strs(storage_path,domain_name)
            
            newlines = [ads_global_strs+localstrs+ads_home_strs]
            updated_file = support.fileutil.file_option.FileOption(SAMBA_CONF_FILE)
            updated_file.write_lines_file(newlines)
    finally:
        support.lock_option.lock_release("smb_state_lock")
        
    return True,''

def delete_smdb(share_path):

    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
    module_object.message["field1"] = {"sharepath":share_path}
    flag,msg = module_object.delete()
    if not flag:
        syslog.syslog(syslog.LOG_ERR,'delete share info from database failed')
        return False
    is_vcuuid,vcuuid,vc_ip=support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        hostuuid = support.uuid_op.get_vs_uuid()[1]
        module_object.ip_d = vc_ip
        module_object.message["field1"]["host"] = {"db_name":"hosts","field":{"uuid":hostuuid}}
        flag,msg = module_object.delete_f()
        if not flag:
            syslog.syslog(syslog.LOG_ERR,'delete share info from vc database failed')
    return True
    


def delete_user_group(user_name):

    support.lock_option.lock_acquire("smb_state_lock")
    try:
        FN_USER = '/etc/passwd'
        newlines = []
        f = open(FN_USER)
        lines = f.readlines()
        f.close()

        for x in lines:
            if x.startswith(user_name+':'):
                continue
            newlines.append(x)

        updated_file = support.fileutil.file_option.FileOption(FN_USER)
        updated_file.write_lines_file(newlines)
    except:
        syslog.syslog(syslog.LOG_ERR,'delete user info failed: '+user_name+' '+str(traceback.format_exc()))
    
    try:
        FN_GROUP = '/etc/group'
        newlines = []
        f = open(FN_GROUP)
        lines = f.readlines()
        f.close()

        for x in lines:
            if x.startswith(user_name+':'):
                continue
            newlines.append(x)

        updated_file = support.fileutil.file_option.FileOption(FN_GROUP)
        updated_file.write_lines_file(newlines)
    except:
        syslog.syslog(syslog.LOG_ERR,'delete group info failed: '+user_name+' '+str(traceback.format_exc()))
        
    support.lock_option.lock_release("smb_state_lock")

    return True

def user_loging(user_name):

    return True

def reset_cifs_info(vmuuid):

    try:
        
        vsobj = db_get('host_sharedir',{'vmuuid':vmuuid})
        if not vsobj or not vsobj.get('id'):
            return
        updateparam = {'vmuuid':None}
        db_modify('host_sharedir',{'id':vsobj['id']},updateparam)
    except:
        pass
    
    try:
        is_vcuuid,vcuuid,vcip = support.uuid_op.get_vc_uuid()
        if is_vcuuid and vcuuid!="127.0.0.1":
            
            vsobj = db_get_vc('host_sharedir',{'vmuuid':vmuuid},vcip)
            if not vsobj or not vsobj.get('id'):
                return 
            updateparam = {'vmuuid':None}
            db_modify_vc('host_sharedir',{'id':vsobj['id']},updateparam,vcip)
    except:
        pass
    
    return

def smbqa_alloc_op(event):

    param = event.param
    share_path = param.get('share_path')
    user_name = param.get('user_name')
    vmuuid = param.get('vmuuid') 
    password = param.get('password')
    
    if user_name == "admin":
        return False,'admin cifs dir can not realloced'
    
    try:
        
        objs = db_values('host_sharedir',{'vmuuid':vmuuid})
        if objs:
            return False,'to many dirs for the vm'
    except:
        pass

    hostuuid = support.uuid_op.get_vs_uuid()[1]
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
    module_object.message["field1"] = {"sharepath":share_path,"username":user_name}
    flag,msg = module_object.select()
    if not flag or not msg:
        return False,'realloc cifs dir failed'
    if msg[0]["password"] != password:
        return False,'realloc cifs failed,wrong password.'
    module_object.message["field2"] = {"vmuuid":vmuuid}
    flag,msg = module_object.modify()
    if not flag:
        return False,'realloc cifs dir failed'
    is_vcuuid,vcuuid,vc_ip = support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir",ip_d = vc_ip)
        module_object.message["field1"] = {"sharepath":share_path,"username":user_name,"host":{"db_name":"hosts","field":{"uuid":hostuuid}}}
        module_object.message["field2"] = {"vmuuid":vmuuid}
    flag,msg = module_object.modify_f()
    if not flag:
        return False,'realloc cifs dir failed'
    try:
        

        (flag, _) = operation.vm.vmsys_interface.tools_init_finished(vmuuid)
        if not flag:
            syslog.syslog(syslog.LOG_ERR,"tools not ready")
            return False,'tools not ready'
        try:
            vs_ip = system.network.dns_service_op.get_localhost_ip()
            ips = system.network.dns_service_op.get_localhost_ips()
            path = share_path.split('/')[-1]
            send_message = {"tag":"net_add_connection","ip":vs_ip,"path":path,"username":user_name,"password":password, "ips":ips}
            output = operation.vm.vmsys_op.request_tools(vmuuid,send_message)
            if "successed" != output[0]:
                syslog.syslog(syslog.LOG_ERR,'realloc cifs dir failed: '+output[1])
        except:
            syslog.syslog(syslog.LOG_ERR,"send msg to toos failed"+str(traceback.format_exc()))
        
    except:
        syslog.syslog(syslog.LOG_ERR,'realloc cifs dir failed: '+str(traceback.format_exc()))
        return False,'realloc cifs dir failed'

    return True,''

def delete_share_db_info(share_path):
    
    shareinfo = {}
    try:
        
        shareinfo = db_get('host_sharedir',{'sharepath':share_path})
        if not shareinfo:
            return False,'get share info failed'
    except:
        syslog.syslog(syslog.LOG_ERR,str(traceback.format_exc()))
        return False,'get share info failed'
    return (True, shareinfo)

def smbqa_delete_act(share_path, save_data, Restart="yes"):
    
    (flag, shareinfo) = delete_share_db_info(share_path)
    if not flag:
        return (False, shareinfo)

    if shareinfo.get('vmuuid'):
        vmuuid = shareinfo.get('vmuuid')
        (flag, _) = operation.vm.vm_running_script.check_kvm_process_exist(vmuuid)
        if flag:
            (flag, _) = operation.vm.vmsys_interface.tools_init_finished(vmuuid)
            if flag:
                send_message = {"tag":"net_delete_connection", "shareLst":[share_path.split("/")[-1], ]}
                output = operation.vm.vmsys_op.request_tools(vmuuid,send_message)
                if "successed" != output[0]:
                    syslog.syslog(syslog.LOG_ERR,'relieve cifs dir failed: '+output[1])

    user_name = shareinfo['username'] 
    if not save_data:
        save_data = 'no'
    
    if user_name == 'admin' or user_name == "customshare" or user_name == ".vmshare" or user_name == "share" or user_name == "student-share":
        return False,'user admin should not be deleted'

    flag,msg = delete_smconf(user_name)
    if not flag:
        return False,msg

    flag = delete_user_group(user_name)
    if not flag:
        return False,'delete user info failed'

    #若有用户登录，则强制删除用户，且当前操作的数据不保存
    cmd = 'pkill -u '+user_name
    print cmd
    os.system(cmd)

    cmd = 'userdel '+user_name
    os.system(cmd)

    if save_data == 'no':
        cmd = 'rm -rf '+share_path
        os.system(cmd)

    if "yes" == Restart:
        cmd = '/etc/init.d/smb restart'
        os.system(cmd)
    
        cmd = '/etc/init.d/nmb restart'
        os.system(cmd)

    flag = delete_smdb(share_path)
    if not flag:
        return False,'delete share info from database failed'

    return True,''

def smbqa_delete_op(event):

    param = event.param
    share_path = param.get('share_path')
    save_data = param.get('save_data')
    return smbqa_delete_act(share_path, save_data)

def smbqa_init(event):

    eventexestat = "successed"
    flag,message=smbqa_init_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def smbqa_conf(event):

    eventexestat = "successed"
    flag,message=smbqa_conf_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def smbqa_update(event): 

    eventexestat = "successed"
    flag,message=smbqa_update_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def smbqa_delete(event):

    eventexestat = "successed"
    flag,message=smbqa_delete_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def smbqa_alloc(event):

    eventexestat = "successed"
    flag,message=smbqa_alloc_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def add_vmshare_info(storage_path):

    quota_init(storage_path)

    fn_path = storage_path+'/.vmshare'
    user_name = 'admin'
    sysuser_add(fn_path,user_name)
    flag,message,total_size = get_total_size(storage_path)
    
    quota_adduser(fn_path,user_name,softlimit=total_size,hardlimit=total_size)

    cmd = 'chmod 755 '+fn_path
    os.system(cmd)

    return True

def add_share_info(storage_path):

    cmd = 'mkdir '+storage_path+'/share'
    os.system(cmd)

    share_path = 'share'
    admin_name = 'admin'
    user_name = 'admin'
    newpasswd = '111111'
    confirmpasswd = '111111'

    fn_path = storage_path+'/share'

    if not update_samba_conf(fn_path,share_path,admin_name,user_name):
        syslog.syslog(syslog.LOG_ERR,'update samba config file failed')
        return False

    cmd = "(echo '" + newpasswd + "';echo '" + confirmpasswd + "')|smbpasswd -as "+user_name
    os.system(cmd)
    operation.vhost.smbqa_db.write_user_list(user_name,newpasswd)
    
    cmd = 'chmod 755 '+fn_path
    os.system(cmd)

    return True

def add_customshare_info(storage_path):

    cmd = 'mkdir '+storage_path+'/.vmshare/customshare'
    os.system(cmd)

    share_path = 'customshare'
    admin_name = 'admin'
    user_name = 'admin'
    newpasswd = '111111'
    confirmpasswd = '111111'

    fn_path = storage_path+'/.vmshare/customshare'

    if not update_samba_conf(fn_path,share_path,admin_name,user_name):
        syslog.syslog(syslog.LOG_ERR,'update samba config file failed')
        return False

    cmd = "(echo '" + newpasswd + "';echo '" + confirmpasswd + "')|smbpasswd -as "+user_name
    os.system(cmd)
    operation.vhost.smbqa_db.write_user_list(user_name,newpasswd)
    
    password = newpasswd
    space_size = '0'
    vmuuid = None
    parent_path = None
    
    try:
        total = 0
        shareinfo = os.popen("/bin/df -P | grep %s" % storage_path).readlines()
        for l in shareinfo:
            tmp = l.split(" ")
            infs= [x for x in tmp if x!='']
            space_size = int(infs[2])+int(infs[3])
            break
    except:
        syslog.syslog(syslog.LOG_ERR,'failed to update table host_sharedir'+str(traceback.format_exc()))
        pass
    
    
    flag,message = add_shareinfo(parent_path,fn_path,admin_name,user_name,password,space_size,vmuuid)
    if not flag:
        syslog.syslog(syslog.LOG_ERR,'add customshare info failed')
        return False

    cmd = 'chmod 755 '+fn_path
    os.system(cmd)

    return True

def is_conf_changed():
    
    desf = '/etc/samba/smb.conf'
    f = open(desf)
    lines = f.readlines()
    f.close()
    changed = False
    for line in lines:
        if "[customshare]" in line:
            changed = True
            break
    if changed:
        return True
    else:
        return False

def init_cifs_share():

    srcf = '/usr/vmd/operation/vhost/smb.conf'
    #bkf = '/usr/vmd/operation/vhost/smb.conf.bk'
    desf = '/etc/samba/smb.conf'
    #if os.path.exists(srcf):
    #    cmd = 'rm -f '+desf
    #    os.system(cmd)

    #    cmd = 'cp '+srcf+' '+desf
    #    os.system(cmd)

    #    cmd = 'mv '+srcf +' '+bkf
    #    os.system(cmd)
    
    #vs_uuid = support.uuid_op.get_vs_uuid()[1]
    #local_mount = "/mnt/LOCAL/defaultlocal/l" + vs_uuid + "defaultlocal.defaultlocal"
    storage = operation.vstorage.storage_db_op.get_storage(description = 'defaultlocal')
    if storage:
        local_mount = storage["mount_path"]

    storage_path = local_mount
    
    try:
        total = 0
        shareinfo = os.popen("/bin/df -P | grep %s" % storage_path).readlines()
        for l in shareinfo:
            tmp = l.split(" ")
            infs= [x for x in tmp if x!='']
            total = int(infs[2])+int(infs[3])
            break
        
        shareobj = db_get('host_sharedir',{'sharepath':storage_path+"/.vmshare/customshare"})
        if not shareobj or not shareobj.get('id'):
            return
        updateparam = {'totalsize':total}
        db_modify('host_sharedir',{'id':shareobj['id']},updateparam)
        
    except:
        syslog.syslog(syslog.LOG_ERR,'failed to update table host_sharedir'+str(traceback.format_exc()))
        pass
    
    if is_conf_changed():
        return
    else:
        cmd = 'rm -f '+desf
        os.system(cmd)

        cmd = 'cp '+srcf+' '+desf
        os.system(cmd)

    

    #os.system('mount > /root/mount')

    add_vmshare_info(storage_path)
    add_customshare_info(storage_path)
    add_share_info(storage_path)
    
    cmd = 'chkconfig smb on'
    os.system(cmd)

    cmd = 'chkconfig nmb on'
    os.system(cmd)

    cmd = '/etc/init.d/smb restart'
    os.system(cmd)

    cmd = '/etc/init.d/nmb restart'
    os.system(cmd)
   


    syslog.syslog(syslog.LOG_ERR,"InitSv:init_cifs_share:")

def relieve_vm_op(event):

    param = event.param
    share_path = param.get('share_path')
    user_name = param.get('user_name')
    password = param.get('password')
    vmuuid = param.get('vmuuid')
    storage_path = ""

    hostuuid = support.uuid_op.get_vs_uuid()[1]
    
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir")
    module_object.message["field1"] = {"sharepath":share_path,"username":user_name}
    flag,msg = module_object.select()
    if not flag or not msg:
        return False,'relieve cifs failed'
    if msg[0]["password"] != password:
        return False,'relieve cifs failed,wrong password.'
    module_object.message["field2"] = {"vmuuid":''}
    flag,msg = module_object.modify()
    if not flag:
        return False,'relieve cifs failed'
    is_vcuuid,vcuuid,vc_ip = support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "host_sharedir",ip_d = vc_ip)
        module_object.message["field1"] = {"sharepath":share_path,"username":user_name,"host":{"db_name":"hosts","field":{"uuid":hostuuid}}}
        module_object.message["field2"] = {"vmuuid":''}
    flag,msg = module_object.modify_f()
    if not flag:
        return False,'relieve cifs failed'
    
    try:
       
        (flag, state) = operation.vm.vmsys_interface.tools_init_finished(vmuuid)
        if not flag:
            syslog.syslog(syslog.LOG_ERR,"tools not ready")
            return False,'tools not ready'
        
        send_message = {"tag":"net_delete_connection", "shareLst":[share_path.split("/")[-1], ]}
        output = operation.vm.vmsys_op.request_tools(vmuuid,send_message)
        if "successed" != output[0]:
            syslog.syslog(syslog.LOG_ERR,'relieve cifs dir failed: '+output[1])
        
    except:
        syslog.syslog(syslog.LOG_ERR,'relieve cifs failed: '+str(traceback.format_exc()))
        return False,'relieve cifs failed'
    
    lstr = 'relieve cifs of vm %s' %(vmuuid)
    syslog.syslog(syslog.LOG_ERR,lstr)
    return True,lstr

def cifs_relieve_vm(event):

    eventexestat = "successed"
    flag,message=relieve_vm_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def smbqa_conf_with_size_op(event):

    param = event.param
    parent_path = param.get('parent_path')
    share_path = param.get("share_path")
    admin_name = param.get('admin_name')
    user_name = param.get('user_name')
    password = param.get('password')
    space_size = param.get('space_size') 
    vmuuid = param.get('vmuuid')

    fn_path = parent_path+'/'+share_path

    if username_exists(user_name):
        return False,'the username is in use'

    if sharepath_exists(fn_path):
        return False,'the share path is in use'

    if not os.path.exists(parent_path):
        return False,'storage does not exists'

    if user_name != 'admin':
        sysuser_add(fn_path,user_name)

    quota_adduser(fn_path,user_name,softlimit=space_size,hardlimit=space_size)

    flag,message = samba_adduser(fn_path,share_path,admin_name,user_name,password,password)
    if not flag:
        return flag,message
    flag,message = add_shareinfo(parent_path,fn_path,admin_name,user_name,password,space_size,vmuuid)
    return flag,message

def smbqa_conf_with_size (event):

    eventexestat = "successed"
    flag,message=smbqa_conf_with_size_op(event)
    if not flag:
        eventexestat = "failed"

    updateinfo = {"uuid":event.uuid,"eventexestat":eventexestat,"progress":100, "message":message}
    optevent_db_op.update_optevent(updateinfo,event)
    return (True, "suc")

def smbqa_teacher_student(parent_path, share_path, spaceSize, vmuuid, user_name):

    admin_name = 'admin'
    password = "111111"

    fn_path = parent_path+'/'+share_path
    os.system('mkdir -p %s' % fn_path )

    flag,message = add_shareinfo(parent_path,fn_path,admin_name,user_name,password,spaceSize,vmuuid)
    return flag,message

def batch_tcst_create(shareLst):
    
# # 203401事件端参数检验，重名的不发起操作请求， 增加结果返回
    # shareLst = [{"spaceSize":12333，"name":"xxxx", "shareType":"teacher/student"}, ...]
    # return option_result = {"failed":[{"shareDir":"xxx", "reason":"xxx"}], "successed":[{"shareDir":"xxx","ip":"xxx","spaceSize":12333}, ...]}
    option_result = {"failed":[], "successed":[]}
    # 任务端参数检验，可能和其他主机存在的重名，重名的不发起操作请求，
    shareNames = [x["name"] for x in shareLst] 
    (conflictNames, shareNames) = get_share_conflict_names(shareNames)
    newShareLst = []
    for x in shareLst:
        if x["name"] in conflictNames:
            option_result["failed"].append({"shareDir":x["name"], "reason":"Name conflicts"})
            continue
        newShareLst.append(x)
        
    defaultlocal = operation.vstorage.storage_db_op.get_storage(description = "defaultlocal")
    if not defaultlocal:
        for x in newShareLst:
            option_result["failed"].append({"shareDir":x["name"], "reason":"Defaultlocal storage not exist"})
        return option_result
    for x in newShareLst:
        if x["shareType"] == "teacher":
            # 教师端仅写入数据库
            user_name = "admin"
            (flag, state) = smbqa_teacher_student(defaultlocal["mount_path"]+"/.vmshare/customshare", x["name"], x["spaceSize"], "", user_name)
        else:
            # 学生端标准创建
            share_path = user_name = x["name"]
            admin_name = "admin"
            password = "111111"
            parent_path = defaultlocal["mount_path"]+"/.vmshare/customshare"
            fn_path = parent_path + "/" + x["name"]
            spaceSize = x["spaceSize"]
            
            sysuser_add(fn_path,user_name)
            quota_adduser(fn_path,user_name,softlimit=spaceSize,hardlimit=spaceSize)
            Restart = "no"
            flag, state = samba_adduser(fn_path,share_path,admin_name,user_name,password,password,Restart)
            if flag:
                flag, state = add_shareinfo(parent_path,fn_path,admin_name,user_name,password,spaceSize,None)
        if not flag:
            option_result["failed"].append({"shareDir":x["name"], "reason":"Create share failed"})
        else:
            option_result["successed"].append({"shareDir":x["name"], "spaceSize":x["spaceSize"]})

    # 统一写入smb.conf配置文件，
    # 此操作会进行，从数据库读取配置更新smb.conf
    delete_smconf("student-xxx-xxx")
    cmd = '/etc/init.d/smb restart'
    os.system(cmd)
    cmd = '/etc/init.d/nmb restart'
    os.system(cmd)
    return option_result

def smbqa_batch_tcst_create(event):
    
    # shareLst = [{"spaceSize":12333，"name":"xxxx", "shareType":"teacher/student"}, ...]
    # option_result = {"failed":[{"shareDir":"xxx", "reason":"xxx"}], "successed":[{"shareDir":"xxx","ip":"xxx","spaceSize":12333}, ...]}
    shareLst = event.param["shareLst"]
    option_result = batch_tcst_create(shareLst)
    event.param["option_result"] = option_result
    updateinfo = {"uuid":event.uuid,"eventexestat":"successed","progress":100,"message":""}
    optevent_db_op.update_optevent(updateinfo,event)
    return

def batch_tcst_delete(shareDirs):
    
    option_result = {"failed":[], "successed":[]}
    
    defaultlocal = operation.vstorage.storage_db_op.get_storage(description = "defaultlocal")
    if not defaultlocal:
        for x in shareDirs:
            option_result["failed"].append({"shareDir":x, "reason":"Defaultlocal storage not exist"})
        return option_result
    
    for x in shareDirs:
        
        share_path = defaultlocal["mount_path"]+"/.vmshare/customshare" + "/" + x
        
        (flag, state) = delete_share_db_info(share_path)
        if flag:
            if "admin" != state["username"]:
                # 学生端标准删除
                (flag, state) = smbqa_delete_act(share_path,"no","no")
            else:
                # 教师端特殊处理删除
                flag = delete_smdb(share_path)
                state = ""
                if flag:
                    os.system("rm -rf " + share_path)
        if not flag:
            option_result["failed"].append({"shareDir":x, "reason":state})
        else:
            option_result["successed"].append(x)
        
        
    # 统一写入smb.conf配置文件，
    # 此操作会进行，从数据库读取配置更新smb.conf
    delete_smconf("student-xxx-xxx")
    cmd = '/etc/init.d/smb restart'
    os.system(cmd)
    cmd = '/etc/init.d/nmb restart'
    os.system(cmd)
    return option_result
    
def smbqa_batch_tcst_delete(event):
    
    # shareDirs = ["xxxx",...]
    # option_result = {"failed":[{"shareDir":"xxx", "reason":"xxx"}], "successed":["xxx", ...]}
    shareDirs = event.param["shareDirs"]
    option_result = batch_tcst_delete(shareDirs)
    event.param["option_result"] = option_result
    updateinfo = {"uuid":event.uuid,"eventexestat":"successed","progress":100,"message":""}
    optevent_db_op.update_optevent(updateinfo,event)
    return
    
