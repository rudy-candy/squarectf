import os
import sys
from Crypto.Util import number
from Crypto.PublicKey import RSA
import math
import subprocess

class ImACredentialGhoul:

  def __init__(self, directory_name='/var/www/html/pubkeys', num_keys=512, e=65537):
    self.directory_name = directory_name
    self.num_keys = num_keys
    self.e = e
    self.shared_prime_index_1 = self.num_keys // 3
    self.shared_prime_index_2 = self.shared_prime_index_1 * 2
    self.shared_prime = number.getPrime(2048)

  def progress(self, count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

  def generate_public_keys(self):
    # The keys will be placed in the directory self.directory_name.
    if os.path.isdir(self.directory_name):
      print('{} is already a directory.'.format(self.directory_name))
    else:
      if os.path.isfile(self.directory_name):
        print('{} is the name of an existing file.'.format(self.directory_name))
        quit(1)
      print('Creating dir {}'.format(self.directory_name))
      os.mkdir(self.directory_name)

    print('Generating public keys...')
    for i in range(self.num_keys):
      # Print a progress bar to stdout
      self.progress(i, self.num_keys, f'key:{i:04}')

      p = number.getPrime(2048)
      if i == self.shared_prime_index_1 or i == self.shared_prime_index_2:
        q = self.shared_prime
      else:
        q = number.getPrime(2048)
      n = p * q
      key = RSA.construct((n, self.e))
      f = open(f'{self.directory_name}/u{i:04}.pub', 'wb')
      f.write(key.export_key())
      f.close()

  def create_challenge_users(self):
    # When users successfully ssh into the box, we don't want them to get
    # an interactive shell. We're going to make their login shell simply
    # print the flag and exit so they are disconnected without interaction.
    login_shell = '/usr/local/bin/catflag'
    f = open(login_shell, 'w')
    f.write('#!/bin/bash\n')
    f.write('echo "flag{HEADLINE:new_prime_found_today_at_the_lage_integer_collider}"\n')
    f.close()
    p = subprocess.Popen(['chmod', '+x', login_shell])

    # Now that the program is created, let's make the users and point their
    # login shell at it.
    # The users shall have the same name as their pubkey
    user1 = f'u{self.shared_prime_index_1:04}'
    user2 = f'u{self.shared_prime_index_2:04}'
    subprocess.run(['useradd', '-s', login_shell, '-m', user1])
    subprocess.run(['useradd', '-s', login_shell, '-m', user2])

    # Set up each user with the appropriate public key for ssh login
    subprocess.run(['mkdir', f'/home/{user1}/.ssh'])
    subprocess.run(['chown', f'{user1}:{user1}', f'/home/{user1}/.ssh'])
    subprocess.run(['mkdir', f'/home/{user2}/.ssh'])
    subprocess.run(['chown', f'{user2}:{user2}', f'/home/{user2}/.ssh'])
    p1 = subprocess.run(['ssh-keygen', '-i', '-m', 'PKCS8', '-f', f'{self.directory_name}/{user1}.pub'], capture_output=True, text=True)
    user1_ssh_key = p1.stdout.rstrip()
    p2 = subprocess.run(['ssh-keygen', '-i', '-m', 'PKCS8', '-f', f'{self.directory_name}/{user2}.pub'], capture_output=True, text=True)
    user2_ssh_key = p2.stdout.rstrip()
    f = open(f'/home/{user1}/.ssh/authorized_keys', 'w')
    f.write(f'{user1_ssh_key} {user1}\n')
    f.close()
    f = open(f'/home/{user2}/.ssh/authorized_keys', 'w')
    f.write(f'{user2_ssh_key} {user1}\n')
    f.close()
    subprocess.run(['chown', f'{user1}:{user1}', f'/home/{user1}/.ssh/authorized_keys'])
    subprocess.run(['chown', f'{user2}:{user2}', f'/home/{user2}/.ssh/authorized_keys'])
    subprocess.run(['chmod', '0600', f'/home/{user1}/.ssh/authorized_keys'])
    subprocess.run(['chmod', '0600', f'/home/{user2}/.ssh/authorized_keys'])
    subprocess.run(['touch', f'/home/{user1}/.hushlogin'])
    subprocess.run(['touch', f'/home/{user2}/.hushlogin'])

  def install_and_configure_nginx(self):
    subprocess.run(['apt', 'update'])
    subprocess.run(['apt', '-y', 'install', 'nginx'])
    subprocess.run(['systemctl', 'enable', 'nginx'])
    nginx_config ="""server {
  listen 0.0.0.0:80 default_server;
  root /var/www/html;
  index index.html;
  server_name _;
  location / {
    try_files $uri $uri/ =404;
  }
  location /pubkeys/ {
    autoindex on;
  }
}"""
    f = open('/etc/nginx/sites-available/default', 'w')
    f.write(nginx_config)
    f.close()

    subprocess.run(['mv', 'index.html', '/var/www/html/'])
    subprocess.run(['chmod', '0644', '/var/www/html/index.html'])
    subprocess.run(['rm', '/var/www/html/index.nginx-debian.html'])
    subprocess.run(['systemctl', 'restart', 'nginx'])

  def setup_challenge(self):
    self.generate_public_keys()
    self.create_challenge_users()
    self.install_and_configure_nginx()

  def test_solution_locally(self):
    for i in range(self.num_keys):
      key1 = RSA.import_key(open(f'{self.directory_name}/u{i:04}.pub', 'r').read())
      self.progress(i, self.num_keys, f'searching for match for u{i:04}')
      for j in range(i + 1, self.num_keys):
        key2 = RSA.import_key(open(f'{self.directory_name}/u{j:04}.pub', 'r').read())
        n1 = getattr(key1, 'n')
        n2 = getattr(key2, 'n')
        gcd = math.gcd(n1, n2)
        if gcd == 1:
          continue
        p = gcd
        q = n1 // p
        e = getattr(key1, 'e')
        d = pow(e, -1, (p - 1) * (q - 1))
        private_key = RSA.construct((n1, e, d))
        f = open(f'u{i:04}_solved_private_key', 'wb')
        f.write(private_key.export_key())
        f.close()
        return True
    return False

if __name__ == '__main__':
  chal = ImACredentialGhoul()
  chal.create_challenge_users()
  chal.install_and_configure_nginx()
