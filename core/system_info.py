import os 
import platform
import pwd
import grp

def get_sytem_info():
    uid = os.geteuid()
    user = pwd.getpwuid(uid).pw_name
    group = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]

    info  = {
        "user": user,
        "uid":uid,
        "is_root":uid==0,
        "kernel": platform.release(),
        "os": platform.system()
    }

    return info
