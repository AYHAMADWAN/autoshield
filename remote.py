import paramiko
import stat
import os
import io


class RemoteDeviceHandling:
    def __init__(self, host, user, remote_dir_path, remote_file_path, password=None, key_path=None):
        self.host = host
        self.username = user
        self.remote_dir_path = remote_dir_path
        self.remote_file_path = remote_file_path
        if (password and key_path) or (not password and not key_path):
            return None
        self.password = password
        self.key_path = key_path

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # make a choice for this
        # if the key path was provided use it, otherwise password
        if self.key_path:
            self.ssh.connect(self.host, username=self.username, key_filename=self.key_path)
        else:
            self.ssh.connect(self.host, username=self.username, password=self.password)
        self.sftp = self.ssh.open_sftp() # check how this works

    def sftp_isdir(self, path):
        # check if the path is a valid directory
        try:
            return stat.S_ISDIR(self.sftp.stat(path).st_mode)
        except FileNotFoundError:
            print('Remote Directory:', path, 'Not Found')
            return False
        except Exception as e:
            print('Remote Directory Error:', e)
            return False

    def sftp_isfile(self, path):
        try:
            return stat.S_ISREG(self.sftp.stat(path).st_mode)
        except FileNotFoundError:
            print('Remote File:', path, 'Not Found')
            return False
        except Exception as e:
            print('Remote File Error:', e)
            return False

    def get_remote_file_list(self):
        file_list = []
        try:
            # check for directory errors:
            for dir_path in self.remote_dir_path:
                if dir_path and not self.sftp_isdir(dir_path):
                    return None
            
            for dir_path in self.remote_dir_path:
                file_list.extend([os.path.join(dir_path, f) for f in self.sftp.listdir(dir_path)])#sftp.listdir(remote_dir_path)
            
            for filepath in self.remote_file_path:
                file_list.append(filepath)
            
            # check each of the files inside the list for errors:
            for file in file_list:
                # ignore directories
                if self.sftp_isdir(file):
                    file_list.remove(file)
                # check files errors
                elif not self.sftp_isfile(file):
                    return None
            return file_list
        except Exception as e:
            print('Error:', e)

    def get_remote_file(self, remote_file_path):
        # check the file for errors:
        if not self.sftp_isfile(remote_file_path):
            return None

        with self.sftp.open(remote_file_path, 'r') as file: # add error handling here <-------
            content = file.read().decode()
            return io.StringIO(content) # <----------------------------- CHECK THIS LATER

    def close_ssh_con(self):
        self.ssh.close()
        self.sftp.close()


# input by the user
# host = "192.168.1.2"
# user = "kali"
# remote_path = "/etc/passwd"

# files, sftp, ssh = get_remote_file_list(host, user, '/etc/pam.d', remote_path, password='kali')
# for file in files:
#     print(get_remote_file(sftp, file))

# close_ssh_con(ssh, sftp)