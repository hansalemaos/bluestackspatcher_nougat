import os
import random
import re
import stat
import subprocess
import time
import uuid
from datetime import timedelta, datetime
import pandas as pd
import psutil
import regex
from a_pandas_ex_bstcfg2df import get_bst_config_df
from bstconnect import connect_to_all_localhost_devices
from flatten_everything import flatten_everything
from getdefgateway import get_default_gateway
from getpathfromreg import get_bluestacks_config_file, get_hd_player_bluestacks
from kthread_sleep import sleep
from pdwinauto import get_automation_frame_from_pid
from procobserver import observe_procs
from PrettyColorPrinter import add_printer
from subprocess_print_and_capture import (
    execute_subprocess_multiple_commands_with_timeout_bin2_thread,
)

add_printer(True)


def set_read_write(path):
    os.chmod(path, stat.S_IWRITE)


def set_read_only(path):
    os.chmod(path, stat.S_IREAD)


def normp(path):
    return os.path.normpath(path)


def get_imei_imsi_sim(adb_path, deviceserial):
    adb_path = normp(adb_path)

    def get_codes(v):

        return regex.sub(
            r"\W+",
            "",
            "".join(
                list(
                    flatten_everything(
                        [
                            regex.findall(r"'[^']+'", x.decode("utf-8", "ignore"))
                            for x in v.splitlines()
                        ]
                    )
                )
            ),
        )

    imsi = (
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -c \'service call iphonesubinfo 7 i32 2\'""",
            capture_output=True,
            shell=True,
        )
    ).stdout
    imei = (
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -c \'service call iphonesubinfo 3 i32 2\'""",
            capture_output=True,
            shell=True,
        )
    ).stdout
    sims = (
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -c \'service call iphonesubinfo 11 i32 2\'""",
            capture_output=True,
            shell=True,
        )
    ).stdout
    imsi = get_codes(v=imsi)
    imei = get_codes(v=imei)
    sims = get_codes(v=sims)
    return imei, imsi, sims


def get_all_config(adb_path, deviceserial):
    adb_path = normp(adb_path)
    imei, imsi, sims = get_imei_imsi_sim(adb_path, deviceserial)
    imli = list(
        (
            f"[imei]: [{imei}]".encode(),
            f"[imsi]: [{imsi}]".encode(),
            f"[sims]: [{sims}]".encode(),
        )
    )

    pro = (
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -c \'getprop\'""",
            capture_output=True,
            shell=True,
        )
    ).stdout
    spli = pro.splitlines()
    spli = imli + spli
    daxz = pd.DataFrame(
        [regex.split(r"[\]:]\s*\[", x.decode("utf-8", "ignore").strip()) for x in spli]
    )
    daxz[0] = daxz[0].str.strip().str.strip(" []")
    daxz[1] = daxz[1].str.strip().str.strip(" []")
    daxz.columns = ["aa_key", "aa_value"]
    return daxz


def remove_cache(adb_path, deviceserial):
    adb_path = normp(adb_path)
    pro1 = (
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -c \'rm -r -f /data/dalvik-cache\'""",
            capture_output=True,
            shell=True,
        )
    ).stdout
    pro2 = (
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -c \'for cache in /data/user*/*/*/cache/*; do rm -rf "$cache"; done\'""",
            capture_output=True,
            shell=True,
        )
    ).stdout


def get_random_cellphone_file(
    df22,
    adb_path,
):
    adb_path = normp(adb_path)

    df333 = pd.DataFrame()
    for key, item in df22.iterrows():
        erg = subprocess.run(
            f"\"{adb_path}\" -s localhost:{item.localhost} shell su -c 'ls -R /boot/android/dataFS/propfiles'",
            capture_output=True,
            shell=True,
        ).stdout.decode("utf-8", "ignore")
        df333 = pd.DataFrame(
            [
                x
                for x in erg.splitlines()
                if x.strip() and regex.search(r"^\d+$", x.strip()) is None
            ]
        )
        df333 = df333.rename(columns={0: "aa_path"})
        df333["aa_folder"] = df333["aa_path"].apply(
            lambda x: x if x.endswith(":") else pd.NA
        )
        df333.aa_folder = df333.aa_folder.ffill().str.strip(":")
        df333 = df333.loc[~df333.aa_path.str.contains("^.*:$")].reset_index(drop=True)
        df333["aa_wholepath"] = df333.aa_folder.str.rstrip("/") + "/" + df333.aa_path
        df333 = df333.loc[df333.aa_wholepath.str.contains(r"_\d+$")].reset_index(
            drop=True
        )
        df333["aa_countrycode"] = df333.aa_wholepath.str.extract(r"_(\d+$)")
        df333 = (
            df333.loc[
                ~df333.aa_wholepath.str.contains(
                    "huawei", na=False, regex=True, flags=re.I
                )
            ]
            .reset_index(drop=True)
            .copy()
        )
    return df22, df333


def updatecellconf(adb_path, deviceserial, fileche, delete_cache=True):
    adb_path = normp(adb_path)
    subprocess.run(
        f"""\"{adb_path}\" -s {deviceserial} shell su -c \'mount --all -o remount,rw -t vfat\'"""
    )
    allcfgfiles = [
        ".propfile",
        ".abipropfile",
        ".bluestacks.prop",
        ".def.prop",
        ".vendor.prop",
        ".dfprop",
        ".bstconf.prop",
    ]
    for cf in allcfgfiles:
        subprocess.run(
            f"""\"{adb_path}\" -s {deviceserial} shell su -- rm ./data/{cf}""",
            shell=True,
        )
    #
    # execute_subprocess_multiple_commands_with_timeout_bin2_thread([f'{adb_path}', '-s', deviceserial, 'shell'],
    #                                                               ['su', 'cd boot', 'ls -la', 'mount -o remount,rw /'])

    for cf in allcfgfiles:
        execute_subprocess_multiple_commands_with_timeout_bin2_thread(
            [f"{adb_path}", "-s", deviceserial, "shell"],
            ["su", "mount -o remount,rw /", f"rm ./data/{cf}"],
        )

    # execute_subprocess_multiple_commands_with_timeout_bin2_thread([f'{adb_path}', '-s', deviceserial, 'shell'],
    #                                                               ['su', 'cd boot', 'ls -la', 'mount -o remount,rw /'])

    execute_subprocess_multiple_commands_with_timeout_bin2_thread(
        [f"{adb_path}", "-s", deviceserial, "shell"],
        ["su", "mount -o remount,rw /", "rm -r -f /data/dalvik-cache"],
    )
    execute_subprocess_multiple_commands_with_timeout_bin2_thread(
        [f"{adb_path}", "-s", deviceserial, "shell"],
        ["su", "mount -o remount,rw /", "rm -r -f /data/cache"],
    )

    cm2 = f"su -c 'cp /{fileche} //data/.bluestacks.prop'"
    subprocess.run(f"""\"{adb_path}\" -s {deviceserial} shell {cm2}""", shell=True)

    execute_subprocess_multiple_commands_with_timeout_bin2_thread(
        [f"{adb_path}", "-s", deviceserial, "shell"],
        ["su", "mount -o remount,rw /", f"cp /{fileche} //data/.bluestacks.prop"],
    )

    if delete_cache:
        remove_cache(adb_path, deviceserial)
    fileche = fileche.strip().strip("/").strip()
    subprocess.run(
        f"""\"{adb_path}\" -s {deviceserial} shell su -c \'cp ./{fileche} ./data/.bluestacks.prop\'""",
        shell=True,
    )
    execute_subprocess_multiple_commands_with_timeout_bin2_thread(
        [f"{adb_path}", "-s", deviceserial, "shell"],
        ["su", "mount -o remount,rw /", f"cp ./{fileche} ./data/.bluestacks.prop"],
    )


def get_random_dateinterval(min_days, max_days, format_="%d-%m-%y"):
    delta_ = random.randint(min_days, max_days)
    mind = datetime.today() - timedelta(days=delta_)
    while True:
        try:
            maxd = datetime.today() - timedelta(
                days=random.randint(0, delta_ - min_days)
            )
            break
        except Exception:
            pass
    return mind.strftime(format_), maxd.strftime(format_)


def update_bst_cfg(
    bluestackscfg, device_country_code=b"076", locale=b"pt-BR", country=b"BR"
):
    bluestackscfg = normp(bluestackscfg)
    if isinstance(device_country_code, str):
        device_country_code = device_country_code.encode()
    if isinstance(locale, str):
        locale = locale.encode()
    if isinstance(country, str):
        country = country.encode()
    try:
        defgat = get_default_gateway().encode()
    except Exception:
        defgat = b""
    device_carrier_codes = [
        b"se_72405",
        b"se_310260",
        b"se_310410",
        b"se_44020",
        b"se_44010",
        b"se_302720",
        b"se_23410",
    ]

    devicecode = [
        b"S2",
        b"S3",
        b"S4",
        b"S5",
        b"NOTE",
        b"NOTE2",
        b"NOTE3",
        b"MOTOX",
        b"ASUSZENFONE",
        b"ASUSZENFONE2",
        b"MOTOPLAY",
        b"MI5",
        b"ONEPLUSTWO",
        b"S6",
        b"SONYXPERIAZ3PLUS",
        b"ONEPLUS3T",
        b"htcm8",
        b"BLUESAMSUNG",
        b"NEXUS5",
        b"NEXUS4",
        b"GALAXYNOTE",
        b"S6EDGE",
        b"S7",
        b"S7EDGE",
        b"S8PLUS",
        b"TISSOTSPROUT",
        b"MOTOX4",
        b"ONEPLUS3T",
        b"PIXELXL",
        b"ONEPLUS5",
        b"S8PLUS",
        b"S8",
        b"PIXEL2XL",
        b"MI6",
        b"S9PLUS",
        b"XPERIA_XZ",
        b"S10",
        b"S10PLUS",
        b"NOTE10PLUS",
        b"ASUSROG2",
        b"S105G",
        b"S20ULTRA",
        b"A905G",
        b"A80",
        b"LGV30",
        b"S20PLUS",
        b"S21ULTRA",
        b"ONEPLUS8T",
    ]
    try:
        bluestackscfg = normp(bluestackscfg)
        updatedlines = []
        set_read_write(bluestackscfg)
        with open(bluestackscfg, mode="rb") as f:
            data = f.read()
        for line in data.splitlines():

            if b"""bluestacks_account_id=""" in line:
                line = re.sub(
                    rb"""bluestacks_account_id=.*""",
                    rb'''bluestacks_account_id=""''',
                    line,
                )

            elif b"""ip_gateway_addr=""" in line:
                if defgat:
                    line = re.sub(
                        rb"""ip_gateway_addr=.*""",
                        rb'''ip_gateway_addr="''' + defgat + b'''"''',
                        line,
                    )

            elif b"""ip_guest_addr=""" in line:
                line = re.sub(
                    rb"""ip_guest_addr=.*""", rb'''ip_guest_addr="0.0.0.0"''', line
                )

            elif b"""bluestacks_cdn_url=""" in line:
                line = re.sub(
                    rb"""bluestacks_cdn_url=.*""",
                    rb'''bluestacks_cdn_url="https://cdn3.bluestacks.com"''',
                    line,
                )

            elif b"""bluestacks_cloud_url=""" in line:
                line = re.sub(
                    rb"""bluestacks_cloud_url=.*""",
                    rb'''bluestacks_cloud_url="https://cloud.bluestacks.com"''',
                    line,
                )

            elif b"""bluestacks_cloud_url2=""" in line:
                line = re.sub(
                    rb"""bluestacks_cloud_url2=.*""",
                    rb'''bluestacks_cloud_url2="https://delegate.bluestacks.com"''',
                    line,
                )

            elif b"""bluestacks_eb_url=""" in line:
                line = re.sub(
                    rb"""bluestacks_eb_url=.*""",
                    rb'''bluestacks_eb_url="https://eb.bluestacks.com"''',
                    line,
                )

            elif b"""campaign_hash=""" in line:
                line = re.sub(rb"""campaign_hash=.*""", rb'''campaign_hash=""''', line)

            elif b"""campaign_name=""" in line:
                line = re.sub(rb"""campaign_name=.*""", rb'''campaign_name=""''', line)

            elif b"""country=""" in line:
                line = re.sub(
                    rb"""country=.*""", rb'''country="''' + country + b'''"''', line
                )

            elif b"""dns_server=""" in line:
                line = re.sub(rb"""dns_server=.*""", rb'''dns_server="8.8.8.8"''', line)

            elif b"""dns_server2=""" in line:
                line = re.sub(
                    rb"""dns_server2=.*""", rb'''dns_server2="8.8.8.8"''', line
                )

            elif b"""enable_adb_access=""" in line:
                line = re.sub(
                    rb"""enable_adb_access=.*""", rb'''enable_adb_access="1"''', line
                )

            elif b"""enable_adb_remote_access=""" in line:
                line = re.sub(
                    rb"""enable_adb_remote_access=.*""",
                    rb'''enable_adb_remote_access="0"''',
                    line,
                )

            elif b"""rooting=""" in line:
                line = re.sub(rb"""rooting=.*""", rb'''rooting="1"''', line)

            elif b"""guid=""" in line:
                vax = str(uuid.uuid4()).encode()

                line = re.sub(rb"""guid=.*""", rb'''guid="''' + vax + b'''"''', line)

            elif b"""install_date=""" in line:
                d1, d2 = get_random_dateinterval(
                    min_days=10, max_days=20, format_="%d/%m/%y"
                )
                d1, d2 = d1.encode(), d2.encode()
                line = re.sub(
                    rb"""install_date=.*""",
                    rb'''install_date="''' + d1 + b'''"''',
                    line,
                )

            elif b"""install_id=""" in line:
                vax = str(uuid.uuid4()).encode()

                line = re.sub(
                    rb"""install_id=.*""", rb'''install_id="''' + vax + b'''"''', line
                )

            elif b"""android_google_ad_id=""" in line:
                vax = str(uuid.uuid4()).encode()

                line = re.sub(
                    rb"""android_google_ad_id=.*""",
                    rb'''android_google_ad_id="''' + vax + b'''"''',
                    line,
                )

            elif b"""android_id=""" in line:
                aid = str(uuid.uuid4())[:18].replace("-", "").encode()
                line = re.sub(
                    rb"""android_id=.*""", rb'''android_id="''' + aid + b'''"''', line
                )

            elif b"""boot_duration=""" in line:
                line = re.sub(
                    rb"""boot_duration=.*""", rb'''boot_duration="-1"''', line
                )

            elif b"""device_carrier_code=""" in line:
                dcc = random.choice(device_carrier_codes)
                line = re.sub(
                    rb"""device_carrier_code=.*""",
                    rb'''device_carrier_code="''' + dcc + b'''"''',
                    line,
                )

            elif b"""device_country_code=""" in line:
                line = re.sub(
                    rb"""device_country_code=.*""",
                    rb'''device_country_code="''' + device_country_code + b'''"''',
                    line,
                )

            elif b"""device_custom_brand=""" in line:
                line = re.sub(
                    rb"""device_custom_brand=.*""", rb'''device_custom_brand=""''', line
                )

            elif b"""device_custom_manufacturer=""" in line:
                line = re.sub(
                    rb"""device_custom_manufacturer=.*""",
                    rb'''device_custom_manufacturer="'''
                    + random.choice(devicecode)
                    + b'''"''',
                    line,
                )
                # line = re.sub(
                #     rb"""device_custom_manufacturer=.*""",
                #     rb'''device_custom_manufacturer="''' + b"" + b'''"''',
                #     line,
                # )

            elif b"""device_custom_model=""" in line:
                line = re.sub(
                    rb"""device_custom_model=.*""",
                    rb'''device_custom_model="'''
                    + random.choice(devicecode)
                    + b'''"''',
                    line,
                )
                # line = re.sub(
                #     rb"""device_custom_model=.*""",
                #     rb'''device_custom_model="''' + b"" + b'''"''',
                #     line,
                # )

            elif b"""device_profile_code=""" in line:
                line = re.sub(
                    rb"""device_profile_code=.*""",
                    rb'''device_profile_code="'''
                    + random.choice(devicecode)
                    + b'''"''',
                    line,
                )

            elif b"""enable_root_access=""" in line:
                line = re.sub(
                    rb"""enable_root_access=.*""", rb'''enable_root_access="1"''', line
                )

            elif b"""google_account_logins=""" in line:
                line = re.sub(
                    rb"""google_account_logins=.*""",
                    rb'''google_account_logins=""''',
                    line,
                )

            elif b"""google_login_popup_shown=""" in line:
                line = re.sub(
                    rb"""google_login_popup_shown=.*""",
                    rb'''google_login_popup_shown="0"''',
                    line,
                )

            # elif b"""launch_date=""" in line:
            #     line = re.sub(rb"""launch_date=.*""", rb'''launch_date=""''', line)

            elif b"""session_id=""" in line:
                line = re.sub(rb"""session_id=.*""", rb'''session_id="1"''', line)

            elif b"""launcher_guid=""" in line:
                line = re.sub(rb"""launcher_guid=.*""", rb'''launcher_guid=""''', line)

            elif b"""launcher_version=""" in line:
                line = re.sub(
                    rb"""launcher_version=.*""", rb'''launcher_version=""''', line
                )

            elif b"""locale=""" in line:
                line = re.sub(
                    rb"""locale=.*""", rb'''locale="''' + locale + b'''"''', line
                )

            # elif b"""log_levels=""" in line:
            #     line = re.sub(rb"""log_levels=.*""", rb'''log_levels="*:I"''', line)

            elif b"""machine_id=""" in line:
                vax = str(uuid.uuid4()).encode()

                line = re.sub(
                    rb"""machine_id=.*""", rb'''machine_id="''' + vax + b'''"''', line
                )

            elif b"""media_folder=""" in line:
                line = re.sub(rb"""media_folder=.*""", rb'''media_folder=""''', line)

            elif b"""mute_all_instances=""" in line:
                line = re.sub(
                    rb"""mute_all_instances=.*""", rb'''mute_all_instances="1"''', line
                )

            # elif b"""next_vm_id=""" in line:
            #     line = re.sub(rb"""next_vm_id=.*""", rb'''next_vm_id="1"''', line)

            elif b"""shared_folders=""" in line:
                line = re.sub(
                    rb"""shared_folders=.*""",
                    rb'''shared_folders="InputMapper"''',
                    line,
                )

            # elif b"""hypervisor=""" in line:
            #     line = re.sub(rb"""hypervisor=.*""", rb'''hypervisor="hyperv"''', line)

            # elif b"""version_machine_id=""" in line:
            #     vax = str(uuid.uuid4()).encode()
            #     line = re.sub(
            #         rb"""version_machine_id=.*""",
            #         rb'''version_machine_id="''' + vax + b'''"''',
            #         line,
            #     )
            elif b"""first_boot=""" in line:
                # vax = str(uuid.uuid4()).encode()
                line = re.sub(
                    rb"""first_boot=.*""",
                    rb'''first_boot="1"''',
                    line,
                )

            elif b"""shared_folders=""" in line:
                line = re.sub(
                    rb"""shared_folders=.*""",
                    rb'''shared_folders=""''',
                    line,
                )

            elif b"""create_desktop_shortcuts=""" in line:
                line = re.sub(
                    rb"""create_desktop_shortcuts=.*""",
                    rb'''create_desktop_shortcuts="0"''',
                    line,
                )
            elif b"""enable_discord_integration=""" in line:
                line = re.sub(
                    rb"""enable_discord_integration=.*""",
                    rb'''enable_discord_integration="0"''',
                    line,
                )
            elif b"""enable_gamepad_detection=""" in line:
                line = re.sub(
                    rb"""enable_gamepad_detection=.*""",
                    rb'''enable_gamepad_detection="0"''',
                    line,
                )
            elif b"""enable_programmatic_ads=""" in line:
                line = re.sub(
                    rb"""enable_programmatic_ads=.*""",
                    rb'''enable_programmatic_ads="0"''',
                    line,
                )
            elif b"""enable_sigin_gamelaunch=""" in line:
                line = re.sub(
                    rb"""enable_sigin_gamelaunch=.*""",
                    rb'''enable_sigin_gamelaunch="0"''',
                    line,
                )
            elif b"""android_sound_while_tapping=""" in line:
                line = re.sub(
                    rb"""android_sound_while_tapping=.*""",
                    rb'''android_sound_while_tapping="0"''',
                    line,
                )
            elif b"""enable_notifications=""" in line:
                line = re.sub(
                    rb"""enable_notifications=.*""",
                    rb'''enable_notifications="0"''',
                    line,
                )

            updatedlines.append(line)
        with open(bluestackscfg, mode="wb") as f:
            f.write(b"\n".join(updatedlines))
        return updatedlines
    except Exception as fe:
        print(fe)
        return None


def write_new_config_files(
    df,
    locale="pt-BR",
    country="BR",
    countrycode="076",
    adb_path="adb.exe",
    bluestacks_config=r"C:\ProgramData\BlueStacks_nxt\bluestacks.conf",
):
    adb_path = normp(adb_path)
    bluestacks_config = normp(bluestacks_config)
    for key, item in df.iterrows():
        portnumber = item.localhost
        update_bst_cfg(
            bluestackscfg=bluestacks_config,
            device_country_code=countrycode.encode(),
            locale=locale.encode(),
            country=country.encode(),
        )
        deviceserial = f"localhost:{portnumber}"
        df, allcellfiles = get_random_cellphone_file(
            df,
            adb_path=adb_path,
        )
        fileche = (
            allcellfiles.loc[allcellfiles.aa_countrycode == countrycode]
            .sample()
            .aa_wholepath.iloc[0]
        )
        print(fileche)
        updatecellconf(adb_path, deviceserial, fileche, delete_cache=True)


def get_all_names_and_command_lines_from_running_bluestacks():
    allcommandlines = []
    allnames = []
    for p in psutil.process_iter():
        if p.name().lower() == "hd-player.exe":
            try:
                allcommandlines.append(p.as_dict())
            except Exception as fe:
                pass
    cmdlinestart = [
        " ".join(
            [
                f'start "" "{os.path.normpath(x)}"'.strip() if ini == 0 else x
                for ini, x in enumerate(co["cmdline"])
            ]
        ).strip()
        for co in allcommandlines
        if not allnames.append(co["cmdline"][-1])
    ]
    return list(zip(allnames, cmdlinestart))


def kill_bluestacks_and_get_cmdline(ignore=()):
    if isinstance(ignore, str):
        ignore = [ignore]
    ignore = [str(x).lower() for x in ignore]
    allcommandlines = []
    for p in psutil.process_iter():
        if p.name().lower() == "hd-player.exe":
            try:
                asdi = p.as_dict()
                if str(asdi["cmdline"][-1]).lower() in ignore:
                    continue
                allcommandlines.append(asdi)
                dfxxx = get_automation_frame_from_pid(
                    pids=[p.pid], uia=False, screenshot_folder=None, timeout=30
                )
                dfxxx2 = dfxxx.dropna(subset="aa_all_children")
                dfxxx2.aa_postmessage.iloc[0](0x0012, 0, 0)
            except Exception as fe:
                print(fe)
            try:
                p.kill()
            except Exception as fe:
                print(fe)
                continue

    cmdlinestart = [
        " ".join(
            [
                f'start "" "{os.path.normpath(x)}"'.strip() if ini == 0 else x
                for ini, x in enumerate(co["cmdline"])
            ]
        ).strip()
        for co in allcommandlines
    ]
    return [
        (x.split()[x.split().index("--instance") + 1].strip(), x) for x in cmdlinestart
    ]


def start_bluestacks_and_wait(
    cmdlinestart,
    min_threads_open=85,
    timeoutsearch=5,
    sleeptime=0.1,
    timeoutstart=30,
):
    dfastart = []
    for co in cmdlinestart:
        p = subprocess.Popen(co, shell=True)
        sleep(2)
        isbad = False
        timeoutfinal = time.time() + timeoutstart
        dfacounter = 0
        while True:
            try:
                df = observe_procs(
                    executables=("HD-Player.exe",),
                    pickle_output_path=None,
                    sleeptime=sleeptime,
                    timeout=timeoutsearch,
                )
                df.cmdline = df.cmdline.apply(lambda x: " ".join(x))
                dfa = df.loc[df.num_threads < min_threads_open]
                dfastart = df.loc[list(set(df.index) - set(dfa.index))]
                dfadf = dfa.drop_duplicates(subset="cmdline")
                dfa = dfadf.cmdline.to_list()
                dfastartakk = dfastart.drop_duplicates(subset="cmdline")
                dfastart = dfastartakk.cmdline.to_list()
                print("_______________")
                print("Starting: ")
                print("\n".join(dfa))
                print("Running: ")
                print("\n".join(dfastart))
                if not dfa:
                    dfacounter += 1
                    if dfacounter >= 2:
                        break
                else:
                    if timeoutfinal < time.time() and not dfadf.empty:
                        for k, v in dfadf.iterrows():
                            try:
                                try:
                                    dfxxx = get_automation_frame_from_pid(
                                        pids=[int(v.pid)],
                                        uia=False,
                                        screenshot_folder=None,
                                        timeout=30,
                                    )
                                    dfxxx2 = dfxxx.dropna(subset="aa_all_children")
                                    dfxxx2.aa_postmessage.iloc[0](0x0012, 0, 0)
                                except Exception as fe:
                                    print(fe)
                                psutil.Process(v["pid"]).kill()

                            except Exception as fe:
                                print(fe)
                        isbad = True
                        break
                if isbad:
                    break
            except Exception as fe:
                print(fe)
                continue
    return dfastart


def get_phone_data(adb_path, df):
    adb_path = normp(adb_path)
    return pd.concat(
        df.apply(
            lambda x: pd.concat(
                [
                    pd.DataFrame([x.localhost], columns=["aa_value"]),
                    get_all_config(adb_path, f"localhost:{x.localhost}").set_index(
                        "aa_key"
                    ),
                ],
                axis=0,
            ).T,
            axis=1,
        ).to_list()
    ).rename(columns={0: "adb_port"})


def get_all_installed_bs_ids(
    hdexe=r"C:\Program Files\BlueStacks_nxt\HD-Player.exe",
    conffile=r"C:\ProgramData\BlueStacks_nxt\bluestacks.conf",
):
    hdexe, conffile = normp(hdexe), normp(conffile)
    df = get_bst_config_df(conffile)
    dfids = df.loc[df.aa_key_2 == "instance"].aa_key_3.unique().flatten().tolist()
    instarg = "--instance"
    hdexe = os.path.normpath(hdexe)
    startcommands = [f'start "" "{hdexe}" {instarg} {x}'.strip() for x in dfids]
    return startcommands


class BlueStacksPatcher:
    def __init__(
        self,
        adb_path="adb.exe",
        bluestacks_config=None,
        hdplayer=None,
    ):
        if not bluestacks_config:
            bluestacks_config = get_bluestacks_config_file()
        if not hdplayer:
            hdplayer = get_hd_player_bluestacks()
        self.adb_path = normp(adb_path)
        self.bluestacks_config = normp(bluestacks_config)
        self.hdplayer = normp(hdplayer)
        self.df = pd.DataFrame()
        self.running_instances = []

    def connect_to_all_bluestacks_devices(self, timeout=3):
        self.df = connect_to_all_localhost_devices(
            adb_path=self.adb_path,
            timeout=timeout,
            bluestacks_config=self.bluestacks_config,
        )
        return self.df

    def get_device_information(self):
        if self.df.empty:
            self.connect_to_all_bluestacks_devices(timeout=3)
        return get_phone_data(self.adb_path, self.df).reset_index(drop=True)

    def _patch_config_file(self, locale="pt-BR", country="BR", countrycode="076"):
        if self.df.empty:
            self.connect_to_all_bluestacks_devices(timeout=3)
        write_new_config_files(
            self.df,
            locale=locale,
            country=country,
            countrycode=countrycode,
            adb_path=self.adb_path,
            bluestacks_config=self.bluestacks_config,
        )

    def get_all_running_bluestacks_instances(self):
        try:
            self.running_instances = (
                get_all_names_and_command_lines_from_running_bluestacks()
            )
            retu = [list(f) for f in zip(*self.running_instances)]
            if len(retu) == 2:
                return retu
            else:
                return [], []
        except Exception as fe:
            return [], []

    def get_all_installed_bluestacks_instances(self):
        cmdlinestart = get_all_installed_bs_ids(
            hdexe=self.hdplayer,
            conffile=self.bluestacks_config,
        )
        try:
            return [
                (x.split()[x.split().index("--instance") + 1].strip())
                for x in cmdlinestart
            ], cmdlinestart
        except Exception as fe:
            return [], []

    def get_all_offline_instances(self):
        allname, allcmd = self.get_all_installed_bluestacks_instances()
        allnamerun, allcmdrun = self.get_all_running_bluestacks_instances()
        return list(set(allname) - set(allnamerun))

    def kill_running_bluestacks_instances(self, ignore=()):
        killedinst = kill_bluestacks_and_get_cmdline(ignore=ignore)
        try:
            self.connect_to_all_bluestacks_devices(timeout=3)
            return [list(f) for f in zip(*killedinst)]
        except Exception:
            return [], []

    def start_bluestacks_instances(
        self,
        instances=(),
        min_threads_open=85,
        timeoutsearch=3,
        sleeptime=0.1,
        timeoutstart=25,
    ):
        instarg = "--instance"
        startcommands = [
            f'start "" "{self.hdplayer}" {instarg} {x}'.strip() for x in instances
        ]
        dfastart = start_bluestacks_and_wait(
            startcommands,
            min_threads_open=min_threads_open,
            timeoutsearch=timeoutsearch,
            sleeptime=sleeptime,
            timeoutstart=timeoutstart,
        )
        self.connect_to_all_bluestacks_devices(timeout=3)
        return dfastart

    def get_new_imei_imsi(
        self,
        locale="pt-BR",
        country="BR",
        countrycode="076",
        ignore=(),
        min_threads_open=85,
        timeoutsearch=5,
        sleeptime=0.1,
        timeoutstart=25,
    ):
        oldinfo = self.get_device_information()
        if self.df.empty:
            self.connect_to_all_bluestacks_devices(timeout=3)
        namerunningbst, cmdlinerunningbst = self.get_all_running_bluestacks_instances()
        self._patch_config_file(locale=locale, country=country, countrycode=countrycode)
        self.kill_running_bluestacks_instances(ignore=ignore)
        (
            namerunningbst2,
            cmdlinerunningbst2,
        ) = self.get_all_running_bluestacks_instances()
        tostart = list(set(namerunningbst) - set(namerunningbst2))
        self.start_bluestacks_instances(
            instances=tostart,
            min_threads_open=min_threads_open,
            timeoutsearch=timeoutsearch,
            sleeptime=sleeptime,
            timeoutstart=timeoutstart,
        )
        self.connect_to_all_bluestacks_devices(timeout=3)
        newinfo = self.get_device_information()
        # self._patch_config_file(locale=locale, country=country, countrycode=countrycode)
        return oldinfo, newinfo

    def update_imei_imsi_when_p_running_more_than_x_seconds(
        self,
        seconds=3600,
        locale="pt-BR",
        country="BR",
        countrycode="076",
        ignore=(),
        min_threads_open=85,
        timeoutsearch=5,
        sleeptime=0.1,
        timeoutstart=25,
    ):
        ignore2 = []
        for p in psutil.process_iter():
            try:
                if p.name().lower() == "hd-player.exe":
                    t = p.create_time()
                    uptime = time.time() - t
                    if uptime < seconds:
                        ignore2.append(p.as_dict()["cmdline"][-1])
            except Exception as fe:
                print(fe)
                continue
        ignore = list(flatten_everything([ignore, ignore2]))
        return self.get_new_imei_imsi(
            locale=locale,
            country=country,
            countrycode=countrycode,
            ignore=ignore,
            min_threads_open=min_threads_open,
            timeoutsearch=timeoutsearch,
            sleeptime=sleeptime,
            timeoutstart=timeoutstart,
        )

    def start_all_offline_instances(
        self,
        min_threads_open=85,
        timeoutsearch=5,
        sleeptime=0.1,
        timeoutstart=25,
    ):
        offlineinst = self.get_all_offline_instances()
        dfs = self.start_bluestacks_instances(
            instances=offlineinst,
            min_threads_open=min_threads_open,
            timeoutsearch=timeoutsearch,
            sleeptime=sleeptime,
            timeoutstart=timeoutstart,
        )
        return dfs
