# Updates IMEI/IMSI on BlueStacks 5.11.1002 / N32 / 32 bit / Android Nougat (probably other versions as well)

## Make a backup of your BlueStacks folder before using it! 

### You must root your BlueStacks instances! 

#### pip install bluestackspatcher-nougat 

```python
from bluestackspatcher_nougat import BlueStacksPatcher
bstackpatcher = BlueStacksPatcher(
    adb_path="C:\\Users\\Gamer\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe",
    bluestacks_config=r"C:\ProgramData\BlueStacks_nxt\bluestacks.conf",
    hdplayer=r"C:\Program Files\BlueStacks_nxt\HD-Player.exe",
)
bstackpatcher.connect_to_all_bluestacks_devices(timeout=3) # Always connect to all devices before you do any action

a, b = bstackpatcher.get_new_imei_imsi(
    locale="pt-BR",
    country="BR",
    countrycode="076",
    ignore=(),
    min_threads_open=85,
    timeoutsearch=5,
    sleeptime=0.1,
    timeoutstart=25,
)
print(a)
print(b)

```