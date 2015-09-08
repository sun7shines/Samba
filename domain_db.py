# -*- coding: utf-8 -*-

import syslog
import traceback

import support.fileutil.directory_option
import support.uuid_op
import dbmodule.db_module_interface

from dbmodule.db_op import *


def get_domain_info(vsuuid=None):
    
    if not vsuuid:
        vsuuid = support.uuid_op.get_vs_uuid()[1]
    try:   
       
        hostobj = db_get('hosts',{'uuid':vsuuid})
        if not hostobj or not hostobj.get("id"):
            return None
        domain_obj = db_get('domain',{'host_id':hostobj.get('id')})
        return domain_obj
    except:
        return None
    
def insert_domain_info(domain_name,domain_ip,admin_name,password,storage_path,vsuuid=None):
    
    if not vsuuid:
        vsuuid = support.uuid_op.get_vs_uuid()[1]
        
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "hosts")
    field = {}
    field["uuid"] = vsuuid
    module_object.message["field1"] = field
    flag,msg = module_object.select()
    if flag:
        host_id=msg[0]["id"]
    else:
        return False,'insert domain info failed'
    
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "domain")
    field = {"host_id":host_id,"domainname":domain_name,"domainip":domain_ip,"adminname":admin_name,"password":password,"storagepath":storage_path}
    module_object.message["field1"] = field
    flag,msg=module_object.insert()
    if not flag:
        return False,'insert domain info failed'
    is_vcuuid,vcuuid,vc_ip=support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object = dbmodule.db_module_interface.DbMessageObject(ip_d=vc_ip,db_name = "hosts")
        field = {}
        field["uuid"] = vsuuid
        module_object.message["field1"] = field
        flag,msg = module_object.select()
        if flag:
            host_id=msg[0]["id"]
        else:
            return False,'insert domain info failed'
        module_object = dbmodule.db_module_interface.DbMessageObject(ip_d=vc_ip,db_name = "domain")
        field = {"host_id":host_id,"domainname":domain_name,"domainip":domain_ip,"adminname":admin_name,"password":password,"storagepath":storage_path}
        module_object.message["field1"] = field
        flag,msg=module_object.insert()
        if flag:
            return True,""
        else:
            return False,'insert domain info failed'
    return True,""



def delete_domain_info(vsuuid=None):
    
    try:
        if not vsuuid:
            vsuuid = support.uuid_op.get_vs_uuid()[1]
         
        hostobj = db_get('hosts',{'uuid':vsuuid})
        if not hostobj:
            return False,'delete domain info failed'
        db_delete('domain',{'host_id':hostobj.get('id')})
        
        is_vcuuid,vcuuid,vcip=support.uuid_op.get_vc_uuid()
        if is_vcuuid and vcuuid!="127.0.0.1":
            
            hostobj = db_get_vc('hosts',{'uuid':vsuuid},vcip)
            if not hostobj:
                return False,'delete domain info failed'
            db_delete_vc('domain',{'host_id':hostobj.get('id')},vcip)
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'delete_domain_info: '+str(traceback.format_exc()))
        return False,'delete domain info failed'   
    
def update_domain_storage(storage_path,vsuuid=None):  
    
    if not vsuuid:
        vsuuid = support.uuid_op.get_vs_uuid()[1]
        
    module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "hosts")
    field = {}
    field["uuid"] = vsuuid
    module_object.message["field1"] = field
    flag,msg=module_object.select()
    if flag:
        host_id = msg[0]["id"]
    else:
        return False,'update domain storage failed'


    
    is_vcuuid,vcuuid,vc_ip=support.uuid_op.get_vc_uuid()
    if is_vcuuid and vcuuid!="127.0.0.1":
        module_object = dbmodule.db_module_interface.DbMessageObject(ip_d=vc_ip,db_name = "hosts")
        field = {}
        field["uuid"] = vsuuid
        module_object.message["field1"] = field
        flag,msg=module_object.select()
        if flag:
            host_id_invc = msg[0]["id"]
        else:
            return False,'update domain storage failed'


    # not end
    
    try:
        module_object = dbmodule.db_module_interface.DbMessageObject(db_name = "domain")
        field = {}
        field["host"] = host_id
        module_object.message["field1"] = field
        field2 = {"storagepath":storage_path}
        module_object.message["field2"] = field2
        flag,msg = module_object.modify()
        if not flag:
            return False,'update domain storage failed'
        
        is_vcuuid,vcuuid,vc_ip=support.uuid_op.get_vc_uuid()
        if is_vcuuid and vcuuid!="127.0.0.1":
            module_object.ip_d = vc_ip
            field = {}
            field["host"] = host_id_invc
            module_object.message["field1"] = field
            field2 = {}
            field2 = {"storagepath":storage_path}
            module_object.message["field2"] = field2
            flag,msg = module_object.modify()
            if not flag:
                return False,'update domain storage failed'


        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'update_domain_storage: '+str(traceback.format_exc()))
        return False,'update domain storage failed'
        
def insert_domain_user_info(smb_user,total_size,used_size,vsuuid):
    
    #以M为单位
    #total_size = total_size/1024
    try:
        
        hostobj = db_get('hosts',{'uuid':vsuuid})
        if not hostobj:
            return False,'insert domain user info failed'
        domainobj = db_get('domain',{'host_id':hostobj.get('id')})
        if not domainobj:
            return False,'insert domain user info failed'
        insertparam = {'domain_id':domainobj.get('id'),
                       'username':smb_user,
                       'totalsize':total_size,
                       'usedsize':used_size}
        flag,msg = db_save('domain_users',insertparam)
        if not flag:
            return False,msg
        
        is_vcuuid,vcuuid,vcip=support.uuid_op.get_vc_uuid()
        if is_vcuuid and vcuuid!="127.0.0.1":
            hostobj = db_get_vc('hosts',{'uuid':vsuuid},vcip)
            if not hostobj:
                return False,'insert domain user info failed'
            domainobj = db_get_vc('domain',{'host_id':hostobj.get('id')},vcip)
            if not hostobj:
                return False,'insert domain user info failed'
            insertparam = {'domain_id':domainobj.get('id'),
                           'username':smb_user,
                           'totalsize':total_size,
                           'usedsize':used_size}
            flag,msg = db_save_vc('domain_users',insertparam,vcip)
            if not flag:
                return False,msg
    except:
        syslog.syslog(syslog.LOG_ERR,'insert_domain_user_info: '+str(traceback.format_exc()))
        return False,'insert domain user info failed'

def get_domain_user_info(user_name,vsuuid=None):
    
    if not vsuuid:
        vsuuid = support.uuid_op.get_vs_uuid()[1]
    try:   
        
        hostobj = db_get('hosts',{'uuid':vsuuid})
        if not hostobj:
            return None
        domain_obj = db_get('domain',{'host_id':hostobj.get('id')})
        if not domain_obj:
            return None
        dmuser_obj = db_get('domain_users',{'domain_id':domain_obj.get('id'),'username':user_name})
        return dmuser_obj
    except:
        return None
      
def update_domain_user_info(smb_user,quota_size,vsuuid=None):
    
    #quota_size = quota_size/1024
    try:
        if not vsuuid:
            vsuuid = support.uuid_op.get_vs_uuid()[1]
           
        hostobj = db_get('hosts',{'uuid':vsuuid})
        if not hostobj:
            return False,'update domain user info failed'
        domain_obj = db_get('domain',{'host_id':hostobj.get('id')})
        if not domain_obj:
            return False,'update domain user info failed'
        dmuser_obj = db_get('domain_users',{'domain_id':domain_obj.get('id'),'username':smb_user})
        if not domain_obj:
            return False,'update domain user info failed'
        updateparam = {'totalsize':quota_size}
        flag,msg = db_modify('domain_users',{'id':dmuser_obj.get('id')},updateparam)
        if not flag:
            return False,msg
        is_vcuuid,vcuuid,vcip=support.uuid_op.get_vc_uuid()
        if is_vcuuid and vcuuid!="127.0.0.1":
            
            hostobj = db_get_vc('hosts',{'uuid':vsuuid},vcip)
            if not hostobj:
                return False,'update domain user info failed'
            domain_obj = db_get_vc('domain',{'host_id':hostobj.get('id')},vcip)
            if not domain_obj:
                return False,'update domain user info failed'
            dmuser_obj = db_get_vc('domain_users',{'domain_id':domain_obj.get('id'),'username':smb_user},vcip)
            if not dmuser_obj:
                return False,'update domain user info failed'
            updateparam = {'totalsize':quota_size}
            flag, msg = db_modify_vc('domain_users',{'id':dmuser_obj.get('id')},updateparam,vcip)
            if not flag:
                return False,msg
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'update_domain_user_info: '+str(traceback.format_exc()))
        return False,'update domain user info failed'
    
def update_used_size(smb_user,used_size,vsuuid=None):
    
    #used_size = used_size/1024
    try:
        if not vsuuid:
            vsuuid = support.uuid_op.get_vs_uuid()[1]
        
        hostobj = db_get('hosts',{'uuid':vsuuid})
        if not hostobj:
            return False,'update domain user used size failed'
        domain_obj = db_get('domain',{'host_id':hostobj['id']})
        if not domain_obj:
            return False,'update domain user used size failed'
        dmuser_obj = db_get('domain_users',{'domain_id':domain_obj['id'],'username':smb_user})
        if not dmuser_obj:
            return False,'update domain user used size failed'
        updateparam = {'usedsize':used_size}
        flag,msg = db_modify('domain_users',{'id':dmuser_obj['id']},updateparam)
        if not flag:
            return False,msg
        is_vcuuid,vcuuid,vcip=support.uuid_op.get_vc_uuid()
        if is_vcuuid and vcuuid!="127.0.0.1":
            
            hostobj = db_get_vc('hosts',{'uuid':vsuuid},vcip)
            if not hostobj:
                return False,'update domain user used size failed'
            domain_obj = db_get_vc('domain',{'host_id':hostobj['id']},vcip)
            if not domain_obj:
                return False,'update domain user used size failed'
            dmuser_obj = db_get_vc('domain_users',{'domain_id':domain_obj['id'],'username':smb_user},vcip)
            if not dmuser_obj:
                return False,'update domain user used size failed'
            updateparam = {'usedsize':used_size}
            flag,msg =db_modify_vc('domain_users',{'id':dmuser_obj['id']},updateparam,vcip)
            if not flag:
                return False,msg
        
        return True,''
    except:
        syslog.syslog(syslog.LOG_ERR,'update_used_size: '+str(traceback.format_exc()))
        return False,'update domain user used size failed'
    
def get_quota_default_size():
    
    try:
        file_name = '/etc/samba/quota_default.conf'
        f = open(file_name)
        lines = f.readlines()
        f.close()
        return int(lines[0].strip().split()[0])
    except:
        syslog.syslog(syslog.LOG_ERR,'get quota default size except: '+str(traceback.format_exc()))
        return 1000000
    return 

def local_username(user_name):

    #允许admin有多个共享路径
    if user_name == "admin":
        return False
    
    shareinfo = db_get('host_sharedir',{'username':user_name})
    if shareinfo:
        return True
    return False 

def sync_doamin_state():
    
    try:
        vsuuid = support.uuid_op.get_vs_uuid()[1]
        domain_obj = get_domain_info(vsuuid)
        if not domain_obj:
            return []
        storage_path = domain_obj.get('storagepath')
        
        user_list = [obj.get('username') for obj in db_values('domain_users',{'domain_id':domain_obj['id']})]
        for username in user_list:
            fn_path = '%s/.vmshare/domain/%s_%s' % (storage_path,('_').join((domain_obj['domainname']).split('.')),username)
            flag, used_size = support.fileutil.directory_option.get_directory_total_size(fn_path)
            if not flag:
                continue
            #used_size = int(used_size)/1024
            update_used_size(username,used_size,vsuuid)
    except:
        syslog.syslog(syslog.LOG_ERR,'sync_doamin_state:'+str(traceback.format_exc()))
        
    return []

