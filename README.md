# Volatility Hacking Team Attribution (attributeht) plugin
This plugin searches a memory dump for evidence of the Hacking Team Galileo Remote Control System (RCS), and attempts to attribute the infection to particular Hacking Team client.


### Background
The 'elite' level implant maps a region of shared memory using a 7-alphanumeric character name in order to prevent the installation of lower-level implants. This shared memory section is fairly unique, and can be detected using a Regex.


###Attribution
In addition, the list of watermarks for Hacking Team clients was leaked, allowing an attempt at attribution to be made by matching the watermark to a client installation.


For more information, see the blog post here: https://www.4armed.com/blog/memory-forensics-detecting-galileo-rcs-windows

##How-to

The folder where the plugin is located should be passed on to Volatility using the `--plugins=` parameter.

> `volatility --plugins=volatility-attributeht --profile=WinXPSP2x86 -f test.raw attributeht`

Running by default will attempt to identify any HT implants on the machine. The following flags affect how the plugin runs:

```  
  -p PID, --pid=PID     Operate on these Process IDs (comma-separated)
  -n NAME, --name=NAME  Operate on these process names (regex)
  -e, --extract         Attempt to extract configuration data from memory
                        
  -D DUMP_DIR, --dump-dir=DUMP_DIR
                        Directory in which to dump configuration files
  -E, --onlyelite       Search for Elite Implants only
  -S, --onlyscout       Search for Scout Implants only
```

### Extracting configurations.

If the --extract flag is used, then the plugin will attempt to recover configuration information from any implants it finds in memory. This includes AES keys for the scout implants, as well as full JSON configurations for the elite level implants. These are saved to the 'DUMP-DIR' location.


## Example Run

An Example run is shown below with the 'extract' option enabled; the memory image for this is available at: http://hyperionbristol.co.uk/uploads/example_WinXPSP2x86.raw

This sample image has two different infections, an elite level infection from one threat actor, and an unmodified development scout infection. The plugin can differentiate between these.

```python
root@4A-JG-Kali:/mnt/ramdisk# volatility --plugins=volatility-attributeht -f example_WinXPSP2x86.raw attributeht --extract --dump-dir=configs
Volatility Foundation Volatility Framework 2.4
Hacking Team Galileo RCS Implant Detection - 4ARMED Ltd
PID  Watermark Process Name     Implant Type   Threat Actor Confidence (Low-Certain)  C2 Server       Configuration File 
300  B3lZ3bup  pippopippo.exe   Scout          VIRGIN       Certain                   10.0.2.4        configs/scout_configuration_300.json
1852 3OqZ1N5a  userinit.exe     Elite/Soldier  FAE-FURLAN   Certain                   None            None
1888 3OqZ1N5a  explorer.exe     Elite/Soldier  FAE-FURLAN   Certain                   None            None
228  3OqZ1N5a  UsbCipHelper.ex  Elite/Soldier  FAE-FURLAN   Certain                   None            None
212  3OqZ1N5a  VBoxTray.exe     Elite/Soldier  FAE-FURLAN   Certain                   None            None
244  3OqZ1N5a  19pivy.exe       Elite/Soldier  FAE-FURLAN   Certain                   None            None
252  3OqZ1N5a  ctfmon.exe       Elite/Soldier  FAE-FURLAN   Certain                   None            None
264  3OqZ1N5a  msmsgs.exe       Elite/Soldier  FAE-FURLAN   Certain                   None            None
292  3OqZ1N5a  rundll32.exe     Elite/Soldier  FAE-FURLAN   Certain                   178.62.50.243   configs/configuration_elite_292_0xb03fe8L.json
300  3OqZ1N5a  pippopippo.exe   Elite/Soldier  FAE-FURLAN   Certain                   None            None

```
### Configuration Files

Example recovered data is shown below for both levels of implant

####Scout Implant
```
{
    "c2_server": "10.0.2.4", 
    "watermark": "B3lZ3bup", 
    "process_name": "pippopippo.exe", 
    "pid": "300", 
    "key_data": {
        "server_key": "4yeN5zu0+il3Jtcb5a1sBcAdjYFcsD9z", 
        "evidence_key": "i6gMR84bxvQovzbhtV-if0SdPMu359ax", 
        "log_key": "uX-o0BOIkiyOyVXH4L3FYhbai-CvMU-_"
    }, 
    "threat_actor": "VIRGIN", 
    "implant_type": "Scout"
}
```

#### Elite Implant
```
{
    "s": {
        "migrated": false, 
        "version": 2012041601, 
        "remove_driver": true, 
        "collapsed": false, 
        "quota": {
            "max": 4194304000, 
            "min": 1048576000
        }, 
        "nohide": [], 
        "type": "desktop", 
        "wipe": false, 
        "advanced": false
    }, 
    "modules": [
        {
            "module": "addressbook"
        }, 
        {
            "module": "application"
        }, 
        {
            "module": "calendar"
        }, 
        {
            "buffer": 512000, 
            "record": true, 
            "compression": 5, 
            "module": "call"
        }, 
        {
            "quality": "med", 
            "module": "camera"
        }, 
        {
            "module": "chat"
        }, 
        {
            "module": "clipboard"
        }, 
        {
            "network": {
                "processes": [], 
                "enabled": false
            }, 
            "synchronize": false, 
            "mic": true, 
            "module": "crisis", 
            "hook": {
                "processes": [], 
                "enabled": true
            }, 
            "camera": true, 
            "call": true, 
            "position": true
        }, 
        {
            "list": false, 
            "module": "device"
        }, 
        {
            "capture": true, 
            "deny": [
                "*\\AppData\\Local*", 
                "*\\AppData\\Roaming*", 
                "*\\Skype\\Plugins\\*", 
                "*\\$RECYCLE.BIN\\*", 
                "*:\\Windows\\*", 
                "*.dll", 
                "*.exe", 
                "*.ini", 
                "*.lnk", 
                "*.ico", 
                "*.tlb", 
                "*.clb", 
                "*.dat", 
                "*.drv", 
                "*.ocx", 
                "*.url", 
                "\\\\.\\*"
            ], 
            "accept": [
                "*.doc", 
                "*.docx", 
                "*.xls", 
                "*.xlsx", 
                "*.ppt", 
                "*.pptx", 
                "*.pps", 
                "*.ppsx", 
                "*.odt", 
                "*.ods", 
                "*.odp", 
                "*.rtf", 
                "*.txt", 
                "*.pdf"
            ], 
            "minsize": 1, 
            "maxsize": 500000, 
            "module": "file", 
            "date": "2015-08-06 00:00:00", 
            "open": false
        }, 
        {
            "usb": false, 
            "mobile": false, 
            "vm": 0, 
            "module": "infection", 
            "factory": "", 
            "local": false
        }, 
        {
            "module": "keylog"
        }, 
        {
            "module": "money"
        }, 
        {
            "mail": {
                "filter": {
                    "dateto": "2100-01-01 00:00:00", 
                    "maxsize": 100000, 
                    "datefrom": "2015-08-06 00:00:00", 
                    "history": true
                }, 
                "enabled": true
            }, 
            "sms": {
                "filter": {
                    "dateto": "2100-01-01 00:00:00", 
                    "datefrom": "2015-08-06 00:00:00", 
                    "history": true
                }, 
                "enabled": true
            }, 
            "module": "messages", 
            "mms": {
                "filter": {
                    "dateto": "2100-01-01 00:00:00", 
                    "datefrom": "2015-08-06 00:00:00", 
                    "history": true
                }, 
                "enabled": true
            }
        }, 
        {
            "threshold": 0.22, 
            "autosense": false, 
            "silence": 5, 
            "module": "mic"
        }, 
        {
            "width": 50, 
            "module": "mouse", 
            "height": 50
        }, 
        {
            "module": "password"
        }, 
        {
            "module": "photo"
        }, 
        {
            "cell": true, 
            "wifi": true, 
            "module": "position", 
            "gps": false
        }, 
        {
            "onlywindow": false, 
            "quality": "med", 
            "module": "screenshot"
        }, 
        {
            "module": "url"
        }
    ], 
    "events": [
        {
            "start": 0, 
            "enabled": true, 
            "ts": "00:00:00", 
            "subtype": "loop", 
            "te": "23:59:59", 
            "event": "timer", 
            "desc": "STARTUP"
        }, 
        {
            "repeat": 1, 
            "start": 1, 
            "enabled": true, 
            "ts": "00:00:00", 
            "delay": 10, 
            "subtype": "loop", 
            "te": "23:59:59", 
            "event": "timer", 
            "desc": "SCREENSHOT"
        }, 
        {
            "repeat": 2, 
            "start": 2, 
            "enabled": true, 
            "ts": "00:00:00", 
            "iter": 1, 
            "delay": 120, 
            "subtype": "loop", 
            "te": "23:59:59", 
            "event": "timer", 
            "desc": "CAMERA"
        }, 
        {
            "repeat": 3, 
            "start": 3, 
            "enabled": true, 
            "ts": "00:00:00", 
            "delay": 900, 
            "subtype": "loop", 
            "te": "23:59:59", 
            "event": "timer", 
            "desc": "POSITION"
        }, 
        {
            "repeat": 4, 
            "enabled": true, 
            "ts": "00:00:00", 
            "delay": 120, 
            "subtype": "loop", 
            "te": "23:59:59", 
            "event": "timer", 
            "desc": "SYNC"
        }
    ], 
    "actions": [
        {
            "subactions": [
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "device"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "call"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "calendar"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "addressbook"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "messages"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "chat"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "url"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "keylog"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "mouse"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "password"
                }, 
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "file"
                }
            ], 
            "desc": "STARTUP"
        }, 
        {
            "subactions": [
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "screenshot"
                }
            ], 
            "desc": "SCREENSHOT"
        }, 
        {
            "subactions": [
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "camera"
                }
            ], 
            "desc": "CAMERA"
        }, 
        {
            "subactions": [
                {
                    "action": "module", 
                    "status": "start", 
                    "module": "position"
                }
            ], 
            "desc": "POSITION"
        }, 
        {
            "subactions": [
                {
                    "mindelay": 0, 
                    "maxdelay": 0, 
                    "wifi": true, 
                    "stop": false, 
                    "bandwidth": 500000, 
                    "cell": false, 
                    "host": "178.62.50.243", 
                    "action": "synchronize"
                }
            ], 
            "desc": "SYNC"
        }
    ]
}
```