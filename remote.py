import paramiko
import stat
import os
import io

def sftp_isdir(sftp, path):
    # check if the path is a valid directory
    #print(path)
    try:
        return stat.S_ISDIR(sftp.stat(path).st_mode)
    except FileNotFoundError:
        print('Remote Directory:', path, 'Not Found')
        return False
    except Exception as e:
        print('Remote Directory Error:', e)
        return False

def sftp_isfile(sftp, path):
    #print(path)
    try:
        return stat.S_ISREG(sftp.stat(path).st_mode)
    except FileNotFoundError:
        print('Remote File:', path, 'Not Found')
        return False
    except Exception as e:
        print('Remote File Error:', e)
        return False


def get_remote_file_list(host, user, remote_dir_path=None, remote_file_path=None, password=None, key_path=None):
    file_list = []
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # make a choice for this

    try:
        # if the key path was provided use it, otherwise password
        if key_path:
            ssh.connect(host, username=user, key_filename=key_path)
        else:
            ssh.connect(host, username=user, password=password)
        
        sftp = ssh.open_sftp() # check how this works

        # check for directory errors:
        if remote_dir_path and not sftp_isdir(sftp, remote_dir_path):
            return None
        
        file_list = [os.path.join(remote_dir_path, f) for f in sftp.listdir(remote_dir_path)]#sftp.listdir(remote_dir_path)
        if remote_file_path:
            file_list.append(remote_file_path)
        
        # check each of the files inside the list for errors:
        for file in file_list:
            if not sftp_isfile(sftp, file):
                return None

        return file_list, sftp, ssh
    except Exception as e:
        print('Error:', e)


def get_remote_file(sftp, remote_file_path):
    # check the file for errors:
    if not sftp_isfile(sftp, remote_file_path):
        return None

    with sftp.open(remote_file_path, 'r') as file:
        content = file.read().decode()
        return io.StringIO(content) # <----------------------------- CHECK THIS LATER

def close_ssh_con(ssh, sftp):
    ssh.close()
    sftp.close()


# input by the user
# host = "192.168.1.2"
# user = "kali"
# remote_path = "/etc/passwd"

# files, sftp, ssh = get_remote_file_list(host, user, '/etc/pam.d', remote_path, password='kali')
# for file in files:
#     print(get_remote_file(sftp, file))

# close_ssh_con(ssh, sftp)