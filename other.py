import paramiko
import stat
import os
import io
import logging
import logging.handlers
import time
from socket import timeout as socket_timeout
import concurrent.futures

class RemoteDeviceHandling:
    def __init__(self, host, user, remote_dir_path, remote_file_path, password=None, key_path=None):
        self.host = host
        self.username = user
        self.remote_dir_path = remote_dir_path
        self.remote_file_path = remote_file_path
        if (password and key_path) or (not password and not key_path):
            raise ValueError("Both password and key_path are either set or unset. Exactly one must be provided.")
        self.password = password
        self.key_path = key_path

        self.do_connect()


    def do_connect(self):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # make a choice for this
            # if the key path was provided use it, otherwise password
            if self.key_path:
                self.ssh.connect(self.host, username=self.username, key_filename=self.key_path, timeout=5)
            else:
                self.ssh.connect(self.host, username=self.username, password=self.password, timeout=5)
            self.sftp = self.ssh.open_sftp() # check how this works
        except paramiko.AuthenticationException:
            raise ValueError(f'Authentication failed for {self.host}')
        except paramiko.SSHException:
            raise ConnectionError(f'SSH error with {self.host}')
        except socket_timeout:
            raise TimeoutError(f'Could not connect to host {self.host}, connection timed out')
        except Exception as e:
            raise RuntimeError(f'Unexpected error while connecting to {self.host}')
    
    def get_con(self):
        return self.ssh

    def sftp_isdir(self, path):
        # check if the path is a valid directory
        try:
            return stat.S_ISDIR(self.sftp.stat(path).st_mode)
        except FileNotFoundError:
            # print('Remote Directory:', path, 'Not Found')
            return False
        except Exception as e:
            # print('Remote Directory Error:', e)
            return False

    def sftp_isfile(self, path):
        try:
            return stat.S_ISREG(self.sftp.stat(path).st_mode)
        except FileNotFoundError:
            # print('Remote File:', path, 'Not Found')
            return False
        except Exception as e:
            # print('Remote File Error:', e)
            return False

    def get_remote_file_list(self):
        file_list = []
        # check for directory errors:
        for dir_path in self.remote_dir_path:
            if dir_path and not self.sftp_isdir(dir_path):
                raise FileNotFoundError(f"Remote directory does not exist: {dir_path}")
        
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
                raise FileNotFoundError(f"Error reading remote file: {file}")
        return file_list

    def get_remote_file(self, remote_file_path):
        # check the file for errors:
        if not self.sftp_isfile(remote_file_path):
            raise FileNotFoundError(f"Error reading remote file: {file}")

        try:
            with self.sftp.open(remote_file_path, 'r') as file:
                content = file.read().decode()
                return io.StringIO(content) # <----------------------------- CHECK THIS LATER   
        except IOError:
            raise IOError(f'Failed to open or read remote file: {remote_file_path}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error while opening remote file: {remote_file_path}')

    def close_ssh_con(self):
        self.ssh.close()
        self.sftp.close()

def setup_logger(name='Autoshield Logger'):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        syslog = logging.handlers.SysLogHandler(address='/dev/log')
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog.setFormatter(formatter)
        logger.addHandler(syslog)

    return logger