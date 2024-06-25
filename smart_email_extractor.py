from sys import exit
from colorama import init, Fore, Style
from os import makedirs
from os.path import isdir, isfile, splitext, expanduser, join as path_join
from re import match, IGNORECASE, split, findall
from csv import reader as csv_reader
from getpass import getpass
from imaplib import IMAP4_SSL, IMAP4
from time import time, time_ns, sleep
from random import randint
from email import message_from_bytes, policy, utils
from datetime import datetime
from validate_email import validate_email
from dns import resolver
from multiprocessing import freeze_support
from multiprocessing.pool import ThreadPool
from functools import partial
from threading import Lock
from gc import collect
from ssl import create_default_context, CERT_NONE

def get_truthy():
  return ('yes', 'no')

def run_extractor():
  render_intro()

  while True:
    request = request_intro()
    if request.upper() in map(str.upper, get_truthy()):
      if request.upper() == 'NO':
        exit()
      else:
        break
    else:
      show_error('\nInvalid input, enter yes/NO.')
      continue

  while True:
    operation = request_operation()

    if operation == '':
      show_error('Operation is required, try again. %s' % inst)
      continue
    elif not operation.isnumeric():
      show_error('\nInvalid input, enter a number. %s' % inst)
      continue
    else:
      operation_int = int(operation)

      if operation_int not in range(1, 3):
        show_error('\nInvalid input, enter a number from 1-2. %s' % inst)
        continue
      else:
        break

  while True:
    folder = request_dir().strip('"')

    if folder == '':
      show_error('Folder is required, try again.')
      continue
    elif isfile(folder):
      show_error('\nFolder cannot be a file, try again.')
      continue
    elif not isdir(folder):
      show_error('\nFolder does not exist, try again.')
      continue
    else:
      break

  while True:
    thread = request_thread()

    if thread == '':
      show_error('Thread is required, try again.')
      continue
    elif not thread.isnumeric():
      show_error('\nInvalid input, enter a number.')
      continue
    else:
      thread_int = int(thread)

      if thread_int not in range(1, 101):
        show_error('\nInvalid input, enter a number from 1-100.')
        continue
      else:
        break

  global operation_code
  global operation_lower
  global operation_ucfirst

  if operation_int == 1:
    operation_code = 'email_addresses'
    operation_lower = 'email addresses'
    operation_ucfirst = 'Email addresses'
  elif operation_int == 2:
    operation_code = 'email_attachments'
    operation_lower = 'email attachments'
    operation_ucfirst = 'Email attachments'

  while True:
    source = request_source()

    if source == '':
      show_error('%s source is required, try again. %s' % (operation_ucfirst, inst))
      continue
    elif not source.isnumeric():
      show_error('\nInvalid input, enter a number. %s' % inst)
      continue
    else:
      source_int = int(source)

      if source_int not in range(1, 6):
        show_error('\nInvalid input, enter a number from 1-5. %s' % inst)
        continue
      else:
        break

  if source_int == 1:
    while True:
      imap_number = request_imap_number()

      if imap_number == '':
        show_error('IMAP number is required, try again. %s' % inst)
        continue
      elif not imap_number.isnumeric():
        show_error('\nInvalid input, enter a number. %s' % inst)
        continue
      else:
        imap_number_int = int(imap_number)

        if imap_number_int not in range(1, 3):
          show_error('\nInvalid input, enter a number from 1-2. %s' % inst)
          continue
        else:
          break

    imap_credential = []

    if imap_number_int == 1:
      while True:
        imap_host = request_imap_host()

        if imap_host == '':
          show_error('IMAP host is required, try again.')
          continue
        elif not match(r'^[\w\.\-]+$', imap_host):
          show_error('\nInvalid IMAP host input, try again.')
          continue
        else:
          break

      while True:
        imap_user = request_imap_user()

        if imap_user == '':
          show_error('IMAP username is required, try again.')
          continue
        else:
          break

      imap_pass = request_imap_pass()

      while True:
        imap_port = request_imap_port()

        if imap_port == '':
          imap_port = 993
          break
        elif not imap_port.isnumeric():
          show_error('\nInvalid input, enter port number.')
          continue
        else:
          break

      while True:
        mailbox_folder = request_mailbox_folder()

        if not mailbox_folder == '' and not match(r'^[a-zA-Z0-9\.\" ]+$', mailbox_folder):
          show_error('\nInvalid mailbox folder input, try again.')
          continue
        else:
          break

      if mailbox_folder:
        imap_credential.append([imap_host, imap_user, imap_pass, imap_port, mailbox_folder])
      else:
        imap_credential.append([imap_host, imap_user, imap_pass, imap_port])
    else:
      while True:
        imap_file = request_imap_file().strip('"')
        imap_filext = splitext(imap_file)[1]

        if imap_file == '':
          show_error('\nFile is required, try again.')
          continue
        elif isdir(imap_file):
          show_error('\nFile cannot be a directory, try again.')
          continue
        elif not isfile(imap_file):
          show_error('\nFile does not exist, try again.')
          continue
        elif not imap_filext.lower() == '.csv':
          show_error('\nOnly csv files are allowed, try again.')
          continue
        else:
          break

      with open(imap_file) as csv_file:
        data = list(csv_reader(csv_file, delimiter=','))

        if data:
          imap_credential = data

    if imap_credential:
      print('\n%s extraction started...\n' % operation_ucfirst)
      start_time = time()
      imap_email_extraction(imap_credential, thread_int, folder)
      end_time = time()
      render_stat(start_time, end_time)
  
  while True:
    1 + 1
    
def save_email_address(msg, key, name, email, folder):
  date = ''
  time = ''
  if msg['Date']:
    date_time_obj = datetime.strptime(msg['Date'], '%a, %d %b %Y %H:%M:%S %z')
    date = date_time_obj.strftime('%Y-%m-%d')
    time = date_time_obj.strftime('%H:%M:%S %z')

  with lock:
    with open(data_path, 'a', encoding='utf-8') as f:
      f.write('%s, %s, %s, %s, %s, %s, %s\n' % (name, email, folder, key.upper(), msg['Subject'], date, time))
  print('[+]  Added ==|%s, %s, %s, %s, %s, %s, %s|== to %s' % (name, email, folder, key.upper(), msg['Subject'], date, time, data_path))

  if not email in unique_email_addresses:
    unique_email_addresses.append(email)

    with lock:
      with open(unique_path, 'a', encoding='utf-8') as f:
        f.write(email + '\n')
    print('[+]  Added %s to %s' % (email, unique_path))
  else:
    print('[-]  Duplicate %s, skipping...' % email)

  name_email = name + ', ' + email
  if not name_email in unique_name_email:
    unique_name_email.append(name_email)

    with lock:
      with open(name_email_path, 'a', encoding='utf-8') as f:
        f.write(name_email + '\n')
    print('[+]  Added %s to %s' % (name_email, name_email_path))
  else:
    print('[-]  Duplicate ==|%s|== skipping from unique name and email addresses' % name_email)

def log_bad_email(email):
  if not email in bad_email:
    bad_email.append(email)

    path = path_join(save_folder, 'bad.txt')
    with lock:
      with open(path, 'a', encoding='utf-8') as f:
        f.write(email + '\n')
    print('[-]  Invalid email address %s, skipping...' % email)

def save_imap_email(msg, key, name, email, folder):
  if email:
    domain = email.split('@', 1)[1]
    if validate_email(email_address=email, check_format=True, check_blacklist=False, check_dns=False, check_smtp=False):
      mx_error = False

      try:
        resolver.resolve(domain, 'MX')
      except:
        mx_error = True
      
      try:
        if mx_error == True:
          resolver.resolve(domain, 'A')
      except:
        log_bad_email(email)
      else:
        save_email_address(msg, key, name, email, folder)
    else:
      log_bad_email(email)
  else:
    print('[-]  Email address not found, skipping...')

def process_imap_email_extract(data, mailbox_folder, msgnum):
  global count
  count += 1
  
  imap, logged_in = connect_to_imap(data, echo=False)

  if imap and logged_in == True:
    imap.select(mailbox_folder, readonly=True)
    typ, msgnum = imap.fetch(msgnum, '(RFC822)')

    if typ.lower() == 'ok' and len(msgnum) > 0:
      msg = message_from_bytes(msgnum[0][1], policy=policy.HTTP)

      if operation_code == 'email_addresses':
        for key in ('From', 'To', 'CC', 'BCC', 'Reply-To'):
          if msg[key]:
            for value in msg[key].split(','):
              name, email_address = utils.parseaddr(value)
              save_imap_email(msg, key, name, email_address, mailbox_folder)
            
            if count == 20000:
              del name
              del email_address
        
        body = ''
        if msg.is_multipart():
          for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))

            if ((content_type == 'text/plain' or content_type == 'text/html') and 'attachment' not in content_disposition):
              body += str(part.get_payload(decode=True))
        else:
          body += str(msg.get_payload(decode=True))

        possible_emails = findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body)
        for email in possible_emails:
          save_imap_email(msg, 'Body', '', email, mailbox_folder)

        if count == 20000:
          del body
          del possible_emails
      elif operation_code == 'email_attachments':
        for key in ('From', 'To', 'CC', 'BCC'):
          if msg[key]:
            for value in msg[key].split(','):
              name, email_address = utils.parseaddr(value)

              found = False
              for part in msg.iter_attachments():
                found = True
                
                if part.is_multipart():
                  for subpart in part.get_payload():
                    if subpart.get_content_disposition() is not None:
                      filename = subpart.get_filename()
                      if filename:
                        path = path_join(save_path, email_address)
                        if not isdir(path):
                          makedirs(path)

                        filepath = path_join(path, filename)
                        with open(filepath, 'wb') as f:
                          f.write(part.get_payload(decode=True))

                        print('[+]  Added email attachment %s' % filepath)
                else:
                  if part.get_content_disposition() is not None:
                    filename = part.get_filename()
                    if filename:
                      path = path_join(save_path, email_address)
                      if not isdir(path):
                        makedirs(path)

                      filepath = path_join(path, filename)
                      with open(filepath, 'wb') as f:
                        f.write(part.get_payload(decode=True))

                      print('[+]  Added email attachment %s' % filepath)

              if not found:
                print('[-]  Email attachment not found, skipping...')

              if count == 20000:
                del filename
                del filepath

            if count == 20000:
              del name
              del email_address

      if count == 20000:
        del msg
    else:
      print('[-]  Message not found, skipping...')
    
    imap.logout()
    if count == 20000:
      del typ
      del msgnum

  if count == 20000:
    count = 0
    sleep(2)
    collect()

def connect_to_imap(data, echo=True):
  imap = None
  context = create_default_context()
  context.check_hostname = False
  context.verify_mode = CERT_NONE

  if echo:
    print('Connecting to %s:%s...' % (data[0], data[3]))

  if int(data[3]) == 143:
    try:
      imap = IMAP4(data[0], data[3])
    except:
      pass
  elif int(data[3]) == 993:
    try:
      imap = IMAP4_SSL(data[0], data[3], ssl_context=context)
    except:
      pass

  if imap == None:
    try:
      imap = IMAP4(data[0], data[3])
    except:
      pass

    if imap == None:
      try:
        imap = IMAP4_SSL(data[0], data[3], ssl_context=context)
      except:
        pass

  logged_in = False
  
  if imap:
    if echo:
      print('Connection successful')
      print('Logging in with email %s and password' % data[1])

    try:
      imap.login(data[1], data[2])
    except:
      if echo:
        print('Login failed!')
      pass
    else:
      logged_in = True
      
      if echo:
        print('Login successful')
      pass
  else:
    if echo:
      print('Connection failed!')
    pass

  return (imap, logged_in)

def imap_email_extraction(imap_credential, thread, folder):
  print('------------------------------------------------')

  global save_folder
  save_folder = path_join(folder, 'Smart Email Extractor', str(time_ns()) + str(randint(100,999)))
  if not isdir(save_folder):
    makedirs(save_folder)

  if operation_code == 'email_addresses':
    unique_folder = path_join(save_folder, 'unique')
    if not isdir(unique_folder):
      makedirs(unique_folder)

    duplicate_folder = path_join(save_folder, 'duplicate')
    if not isdir(duplicate_folder):
      makedirs(duplicate_folder)

  for data in imap_credential:
    if data[0]:
      imap, logged_in = connect_to_imap(data)

      if imap and logged_in == True:
        print('Start extracting %s from all messages...' % operation_lower)

        if operation_code == 'email_addresses':
          global unique_path
          unique_path = path_join(unique_folder, data[1] + '.txt')

          global name_email_path
          name_email_path = path_join(unique_folder, data[1] + '_name_email.csv')
          with open(name_email_path, 'a', encoding='utf-8') as f:
            f.write('Name, Email Address\n')

          global data_path
          data_path = path_join(duplicate_folder, data[1] + '_data.csv')
          with open(data_path, 'a', encoding='utf-8') as f:
            f.write('Name, Email Address, Folder, Header, Subject, Date, Time\n')

          global unique_email_addresses
          global unique_name_email
          global bad_email

          unique_email_addresses = []
          unique_name_email = []
          bad_email = []
        elif operation_code == 'email_attachments':
          global save_path
          save_path = path_join(save_folder, data[1])
          if not isdir(save_path):
            makedirs(save_path)

        if len(data) >= 5 and data[4]:
          process_mailbox_folder(imap, data, data[4], thread)
        else:
          mailboxes = imap.list()
          
          if mailboxes and mailboxes[0].lower() == 'ok' and len(mailboxes) > 1:
            if mailboxes[1]:
              for mailbox in mailboxes[1]:
                mailbox = split(r' \".\" ', mailbox.decode('utf-8'), maxsplit=1)
                if len(mailbox) == 2:
                  process_mailbox_folder(imap, data, mailbox[1], thread)
          else:
            print('No mailbox folder found!')
    else:
      if len(imap_credential) == 1:
        txt = 'ending...'
      else:
        txt = 'skipping to the next...'

      show_error('\nIMAP host is missing, %s' % txt)

    print('------------------------------------------------')

def process_mailbox_folder(imap, data, mailbox_folder, thread):
  print('Scanning folder %s' % mailbox_folder)

  typ, message = imap.select(mailbox_folder, readonly=True)

  if typ.lower() == 'ok':
    typ, msgnums = imap.search(None, 'ALL')
    msgnums = msgnums[0].split()

    imap.logout()
    if typ.lower() == 'ok' and len(msgnums) > 0:
      with ThreadPool(processes=thread) as pool:
        pool.map(partial(process_imap_email_extract, data, mailbox_folder), msgnums)
    else:
      print('Could not find emails in mailbox %s' % data[1])
  else:
    print('Mailbox folder not found!')

def request_intro():
  return input('\nWould you like to proceed? (yes/NO):')

def request_operation():
  return rw_input('''\nWhat operation would you like to perform?\nEnter 1 to extract email addresses from email account(s)\nEnter 2 to extract email attachments from email account(s)''', '')

def request_dir():
  return rw_input('\nEnter save directory (you can drag and drop folder here):', expanduser('~\\Documents'))

def request_source():
  return rw_input('''\nWhere would you like to extract ''' + operation_lower + ''' from?\nEnter 1 to extract ''' + operation_lower + ''' from email account(s) using IMAP\nEnter 2 to extract ''' + operation_lower + ''' from email account(s) using POP3\nEnter 3 to extract ''' + operation_lower + ''' from MBOX file(s)\nEnter 4 to extract ''' + operation_lower + ''' from Maildir folder(s)\nEnter 5 to extract ''' + operation_lower + ''' from EML file(s)''', '')

def request_imap_number():
  return rw_input('''\nHow many IMAP credential(s) do you want to extract ''' + operation_lower + ''' from?\nEnter 1 for single IMAP credential\nEnter 2 for multiple IMAP credential''', '')

def request_imap_file():
  return input('\nYour IMAP credentials file must be a CSV file with multiple line format of IMAP Host,Username,Password,Port. Where Password and Port are both optional. The default port is 993. Your seperator must be comma (,) and you must not specify any field title, only values\nEnter IMAP credentials file (you can drag and drop file here):')

def request_imap_host():
  return input('\nEnter IMAP host:')

def request_imap_user():
  return input('\nEnter IMAP username:')

def request_imap_pass():
  return getpass('\nEnter IMAP password (optional):')

def request_imap_port():
  return input('\nEnter IMAP port (optional, default port is 993):')

def request_mailbox_folder():
  return input('\nEnter mailbox folder (optional):')

def request_thread():
  return rw_input('\nEnter lookup thread (integer 1-100):', '20')

def show_error(msg:str):
  print(Fore.RED + msg + Style.RESET_ALL)

def show_success(msg:str):
  print(Fore.GREEN + msg + Style.RESET_ALL)

def rw_input(prompt, prefill=''):
  try:
    from pyautogui import typewrite
    print(prompt)
    typewrite(prefill)
    return input()
  except(ImportError, KeyError):
    from readline import set_startup_hook, insert_text
    set_startup_hook(lambda: insert_text(prefill))
  
  try:
    return input(prompt)
  finally:
    set_startup_hook()

def render_intro():
  print(Fore.RED + ''' 
 __              __  ___     ___                       ___     ___  __        __  ___  __   __  
/__`  |\\/|  /\\  |__)  |     |__   |\\/|  /\\  | |       |__  \\_/  |  |__)  /\\  /  `  |  /  \\ |__) 
.__/  |  | /~~\\ |  \\  |     |___  |  | /~~\\ | |___    |___ / \\  |  |  \\ /~~\\ \\__,  |  \\__/ |  \\

''' + Fore.GREEN + '''                                                                           v0.0.1 by DmitriBlov
''' + Fore.BLUE + '''
About
+++++''' + Style.RESET_ALL + '''
This program is a command-line software used to speedily extract email addresses and attachments from files or folders, email accounts (through IMAP, POP3, MBOX, MailDir, or EML), WHOIS records, websites, and search engines. It is distributed as freeware
''' + Fore.BLUE + '''
Contact
+++++++''' + Style.RESET_ALL + '''
To reach out to us for feedback, reports, feature requests, etc. Use the contact details below

Telegram Contact: https://t.me/DmitriBlovvv
Skype Contact: live:.cid.e47b29ce4dfd6ec6
Discord Contact: dmitriblov
Telegram Channel: https://t.me/BlovHackingServicesChannel
Telegram Group: https://t.me/BlovHackingServicesChat
''' + Fore.BLUE + '''
Disclaimer
++++++++++''' + Style.RESET_ALL + '''
DmitriBlov or developers at BlovHackingServices will not be held responsible for any misuse of this software. If usage violates the laws of your country or more, do not use this software''' + Fore.YELLOW + '''
--------------------------------------------------------------------------------''' + Style.RESET_ALL + '''
If you like what this software does and/or how it helps you, please consider donating to support our effort and to keep newer versions of this software free. We really appreciate your donations

Bitcoin: bc1q60zfh5zz5qk83e4xu6dh34fnfhkzuplt7nywga
Bitcoin Cash: qreq3z08u4jdwcgg2hf2ry4m850w8qq8uyxtkvy2hf
Ethereum: 0xF13DeAcC1D363D9D955051313b71Edde1a505496
USDT: 0xF13DeAcC1D363D9D955051313b71Edde1a505496
Litecoin: ltc1qtsd5knqly48jujp9gryamfzf0hdfpqfpfe6r8m''')

def render_stat(start_time, end_time):
  print(f'\nFinished in {end_time - start_time} seconds')

if __name__ == '__main__':
  freeze_support()
  init()

  count = 0
  lock = Lock()
  inst = 'Read the prompt below for instructions'
  run_extractor()