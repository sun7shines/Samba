# -*- coding: utf-8 -*-

import syslog
import traceback
import os
import operation.vstorage.storage_db_op

from dbmodule.db_op import *

def get_userdesc_by_basename(base_name):
    
    return [obj.get('username') for obj in db_values('host_sharedir',{'username__startswith':base_name})]

def get_all_share_paths(share_path):
    
    return [obj['sharepath'] for obj in db_values('host_sharedir',{'parentpath':share_path})]

def get_vmuuid(share_path=None,vmuuid=None):
    if share_path:
        
        obj = db_get('host_sharedir',{'sharepath':share_path})
        if obj:
            return obj.get('vmuuid')
        else:
            return None
    elif vmuuid:
        try:
            
            obj = db_get('host_sharedir',{'vmuuid':vmuuid})
            if obj:
                return vmuuid
        except:
            return ""
    return None

def get_smb_conf_type():
    
    file_name = '/etc/samba/smb.conf'
    f = open(file_name)
    lines = f.readlines()
    f.close()
    conf_type = ''
    for line in lines:
        if line.find('security') != -1 and line.find('ads') != -1:
            conf_type = 'ads'
        if line.find('security') != -1 and line.find('user') != -1:
            conf_type = 'user'
            
    return conf_type

def write_to_file(user_name,password,file_name):
    
    try:
        newlines = []
        if os.path.exists(file_name):
            f = open(file_name)
            lines = f.readlines()
            f.close()
            for line in lines:
                x = line.strip()
                if not x:
                    continue
                if x.split()[0] == user_name:
                    continue
                newlines.append(x+'\n')
                
        lstr = '%s %s\n' % (user_name,password)
        newlines.append(lstr) 
        f = open(file_name,'w')
        f.writelines(newlines)
        f.close()
    except:
        syslog.syslog(syslog.LOG_ERR,'write_to_file: '+str(traceback.format_exc()))
    return

def write_user_list(user_name,password):
    
    conf_type = get_smb_conf_type()
    if not conf_type:
        write_to_file(user_name,password,'/etc/samba/users.user')
        write_to_file(user_name,password,'/etc/samba/users.ads')
        
    elif conf_type == 'user':
        write_to_file(user_name,password,'/etc/samba/users.ads')
    
    elif conf_type == 'ads':
        write_to_file(user_name,password,'/etc/samba/users.user')
   
    return True

def smbpasswd_users(file_name):
    
    if not os.path.exists(file_name):
        return True
    try:
        f = open(file_name)
        lines = f.readlines()
        f.close()
        for line in lines:
            x = line.strip().split()
            if len(x) != 2:
                continue
            user_name = x[0]
            password = x[1]
            cmd = "(echo '" + password + "';echo '" + password + "')|smbpasswd -as "+user_name
            os.system(cmd)
        lines = []
        f = open(file_name,'w')
        f.writelines(lines)
        f.close
    except:
        syslog.syslog(syslog.LOG_ERR,'smbpasswd_users: '+str(traceback.format_exc()))
    return True

def get_local_share_strs_by_db(del_name=''):
    
    strs = ''
    try:
        
        localStoragePath = ""
        
        local_shares = db_values('host_sharedir',{})
        for share in local_shares:
            share_path = share['sharepath']
            admin_name = share['adminname']
            user_name = share['username']
            share_name = share_path.split("/")[-1]
            
            if not localStoragePath and user_name == 'admin':
                localStoragePath = "/".join(share_path.split("/")[:3])
            
            if not share["parentpath"]:
                # 根目录本身，在后续有加入strs中
                continue
            
            if del_name == user_name:
                continue
                
            if user_name == 'admin':
                # 教师端特殊处理，使用admin用户，可读写，任意其他用户，都是只读的
                strs = strs + '''
                 
        [%s]
        comment = This is a directory of TS.
        path = %s
        public = no
        admin users = admin
        valid users =
        writable = no
        write list = admin, +staff''' % (share_name, share_path)
            else:
                # 学生端，走标准共享接口
                strs = strs + '''
                 
        [%s]
        comment = This is a directory of TS.
        path = %s
        public = no
        admin users = %s
        valid users = %s
        writable = yes
        write list = +staff''' % (share_name,share_path,admin_name,user_name)

        if not localStoragePath:
            storage = operation.vstorage.storage_db_op.get_storage(description = 'defaultlocal')
            if storage:
                localStoragePath = storage["mount_path"]
            
        strs = """
        [share]
        comment = This is a directory of TS.
        path = %s/share
        public = no
        admin users = admin
        valid users = admin
        writable = yes
        write list = +staff

        [customshare]
        comment = This is a directory of TS.
        path = %s/.vmshare/customshare
        public = no
        admin users = admin
        valid users = admin
        writable = yes
        write list = +staff""" % (localStoragePath, localStoragePath) + strs
        return True, strs
    except:
        syslog.syslog(syslog.LOG_ERR,'get_local_share_strs_by_db failed' +str(traceback.format_exc()))
        return False,'get_local_share_strs_by_db failed'
        

