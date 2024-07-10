#!/usr/bin/env python3
#
# Copyright (c) 2017-2024 NVIDIA CORPORATION & AFFILIATES.
# Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# main.py
#
# Specific command-line utility for Mellanox platform
#

try:
    import json
    import os
    import time

    import click
    from sonic_py_common import logger
    from sonic_py_common import device_info
    import utilities_common.cli as clicommon
except ImportError as e:
    raise ImportError("%s - required module not found" % str(e))

VERSION = '1.0'

SNIFFER_SYSLOG_IDENTIFIER = "sniffer"

# SDK sniffer env variable
ENV_VARIABLE_SX_SNIFFER = 'SX_SNIFFER_ENABLE'
ENV_VARIABLE_SX_SNIFFER_TARGET = 'SX_SNIFFER_TARGET'

# SDK sniffer file path and name
SDK_SNIFFER_TARGET_PATH = '/var/log/sdk_dbg/'
SDK_SNIFFER_FILENAME_PREFIX = 'sx_sdk_sniffer_'
SDK_SNIFFER_FILENAME_EXT = '.pcap'

# Supervisor config file path
TMP_SNIFFER_CONF_FILE = '/tmp/tmp.conf'
CONTAINER_NAME = 'syncd'
SNIFFER_CONF_FILE = '/etc/supervisor/conf.d/mlnx_sniffer.conf'
SNIFFER_CONF_FILE_IN_CONTAINER = CONTAINER_NAME + ':' + SNIFFER_CONF_FILE
# Command to restart swss service
COMMAND_RESTART_SWSS = ['systemctl', 'restart', 'swss.service']


# Global logger instance
log = logger.Logger(SNIFFER_SYSLOG_IDENTIFIER)

# generate sniffer target file name include a time stamp.
def sniffer_filename_generate(path, filename_prefix, filename_ext):
    if not os.path.exists(path):
        os.makedirs(path)
    time_stamp = time.strftime("%Y%m%d%H%M%S")
    filename = path + filename_prefix + time_stamp + filename_ext
    return filename


# write environment variable in local tmp file for sniffer
def env_variable_write(env_variable_string):
    conf_file = open(TMP_SNIFFER_CONF_FILE, 'a')
    if os.path.getsize(TMP_SNIFFER_CONF_FILE) == 0:
        conf_file.write('[program:syncd]\n')
    conf_file.write(env_variable_string)
    conf_file.close()


def env_variable_read(env_variable_name):
    conf_file = open(TMP_SNIFFER_CONF_FILE, 'r')
    for env_variable_string in conf_file:
        if env_variable_string.find(env_variable_name) >= 0:
            break
    else:
        env_variable_string = ''
    conf_file.close()
    return env_variable_string


def env_variable_delete(delete_line):
    conf_file = open(TMP_SNIFFER_CONF_FILE, 'r+')
    all_lines = conf_file.readlines()
    conf_file.seek(0)
    for line in all_lines:
        if line != delete_line:
            conf_file.write(line)
    conf_file.truncate()
    conf_file.close()


def conf_file_copy(src, dest):
    command = ['docker', 'cp', str(src), str(dest)]
    clicommon.run_command(command)


def conf_file_receive():
    command = ['docker', 'exec', str(CONTAINER_NAME), 'bash', '-c', 'touch ' + str(SNIFFER_CONF_FILE)]
    clicommon.run_command(command)
    conf_file_copy(SNIFFER_CONF_FILE_IN_CONTAINER, TMP_SNIFFER_CONF_FILE)


def config_file_send():
    conf_file_copy(TMP_SNIFFER_CONF_FILE, SNIFFER_CONF_FILE_IN_CONTAINER)


# set supervisor conf file for sniffer enable
def sniffer_env_variable_set(enable, env_variable_name, env_variable_string=""):
    ignore = False
    conf_file_receive()
    env_variable_exist_string = env_variable_read(env_variable_name)
    if env_variable_exist_string:
        if enable is True:
            click.echo("sniffer is already enabled, do nothing")
            ignore = True
        else:
            env_variable_delete(env_variable_exist_string)
    else:
        if enable is True:
            env_variable_write(env_variable_string)
        else:
            click.echo("sniffer is already disabled, do nothing")
            ignore = True

    if not ignore:
        config_file_send()

    command = ['rm', '-rf', str(TMP_SNIFFER_CONF_FILE)]
    clicommon.run_command(command)

    return ignore


# restart the swss service with command 'service swss restart'
def restart_swss():
    try:
        clicommon.run_command(COMMAND_RESTART_SWSS)
    except OSError as e:
        log.log_error("Not able to restart swss service, %s" % str(e), True)
        return 1
    return 0


# ==================== CLI commands and groups ====================

# Callback for confirmation prompt. Aborts if user enters "n"
def _abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


# 'mlnx' group
@click.group()
def mlnx():
    """ Mellanox platform configuration tasks """
    pass


# 'sniffer' group
@mlnx.group()
def sniffer():
    """ Utility for managing Mellanox SDK/PRM sniffer """
    pass


# 'sdk' subgroup
@sniffer.group()
def sdk():
    """SDK Sniffer - Command Line to enable/disable SDK sniffer"""
    pass


@sdk.command()
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false, expose_value=False,
              prompt='Swss service will be restarted, continue?')
def enable():
    """Enable SDK Sniffer"""
    click.echo("Enabling SDK sniffer")
    sdk_sniffer_enable()
    click.echo("Note: the sniffer file may exhaust the space on /var/log, please disable it when you are done with this sniffering.")


@sdk.command()
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false, expose_value=False,
              prompt='Swss service will be restarted, continue?')
def disable():
    """Disable SDK Sniffer"""
    click.echo("Disabling SDK sniffer")
    sdk_sniffer_disable()


def sdk_sniffer_enable():
    """Enable SDK Sniffer"""
    sdk_sniffer_filename = sniffer_filename_generate(SDK_SNIFFER_TARGET_PATH,
                                                     SDK_SNIFFER_FILENAME_PREFIX,
                                                     SDK_SNIFFER_FILENAME_EXT)
    sdk_sniffer_env_variable_dict = {ENV_VARIABLE_SX_SNIFFER: "1" + ",",
                                     ENV_VARIABLE_SX_SNIFFER_TARGET: sdk_sniffer_filename}
    sdk_sniffer_env_variable_string = "environment="

    for env_variable_name, env_variable_value in sdk_sniffer_env_variable_dict.items():
        sdk_sniffer_env_variable_string += (env_variable_name + "=" + env_variable_value)

    sdk_sniffer_env_variable_string += "\n"

    ignore = sniffer_env_variable_set(enable=True, env_variable_name=ENV_VARIABLE_SX_SNIFFER,
                                      env_variable_string=sdk_sniffer_env_variable_string)
    if not ignore:
        err = restart_swss()
        if err != 0:
            return
        click.echo('SDK sniffer is Enabled, recording file is %s.' % sdk_sniffer_filename)
    else:
        pass


def sdk_sniffer_disable():
    """Disable SDK Sniffer"""

    ignore = sniffer_env_variable_set(enable=False, env_variable_name=ENV_VARIABLE_SX_SNIFFER)
    if not ignore:
        err = restart_swss()
        if err != 0:
            return
        click.echo("SDK sniffer is Disabled.")
    else:
        pass


@mlnx.group()
def im():
    """ Utility for managing Mellanox module host management mode """
    pass


@im.command()
def enabled():
    """ Enable module host management mode"""
    platform_dir, hwsku_dir = device_info.get_paths_to_platform_and_hwsku_dirs()
    sai_profile = os.path.join(hwsku_dir, 'sai.profile')
    from sonic_platform.device_data import DeviceDataManager
    if DeviceDataManager.is_module_host_management_mode():
        click.echo('Module host management mode is already enabled')
        return 0
    
    with open(sai_profile, 'a') as f:
        f.write('SAI_INDEPENDENT_MODULE_MODE=1\n')
        
    control_file = os.path.join(platform_dir, 'pmon_daemon_control.json')
    with open(control_file, 'r') as f:
        content = json.load(f)
        
    control_file = os.path.join(hwsku_dir, 'pmon_daemon_control.json')
    with open(control_file, 'w') as f:
        content['skip_xcvrd_cmis_mgr'] = False
        content['enable_xcvrd_sff_mgr'] = True
        json.dump(content, f)
        
    src = '/usr/share/sonic/device/x86_64-mlnx_msn4700-r0/Mellanox-SN4700-O8C48/media_settings.json'
    if not os.path.exists(src):
        src = '/usr/share/sonic/device/x86_64-mlnx_msn4700-r0/Mellanox-SN4700-O8V48/media_settings.json'
    dst = os.path.join(hwsku_dir, 'media_settings.json')
    clicommon.run_command(['cp', src, dst])
    
    src = '/usr/share/sonic/device/x86_64-mlnx_msn4700-r0/Mellanox-SN4700-O8C48/optics_si_settings.json'
    if not os.path.exists(src):
        src = '/usr/share/sonic/device/x86_64-mlnx_msn4700-r0/Mellanox-SN4700-O8V48/optics_si_settings.json'
    dst = os.path.join(hwsku_dir, 'optics_si_settings.json')
    clicommon.run_command(['cp', src, dst])


@im.command()
def disabled():
    """ Disable module host management mode"""
    _, hwsku_dir = device_info.get_paths_to_platform_and_hwsku_dirs()
    sai_profile = os.path.join(hwsku_dir, 'sai.profile')
    from sonic_platform.device_data import DeviceDataManager
    if not DeviceDataManager.is_module_host_management_mode():
        click.echo('Module host management mode is already disabled')
        return 0
    
    with open(sai_profile, 'r') as f:
        lines = f.readlines()
        new_lines = []
        for line in lines:
            if line.find('SAI_INDEPENDENT_MODULE_MODE') != -1:
                continue
            new_lines.append(line)
            
    with open(sai_profile, 'w') as f:
        f.writelines(new_lines)
        
    control_file = os.path.join(hwsku_dir, 'pmon_daemon_control.json')
    clicommon.run_command(['rm', '-f', control_file])
    
    file_path = os.path.join(hwsku_dir, 'media_settings.json')
    clicommon.run_command(['rm', '-f', file_path])
    
    file_path = os.path.join(hwsku_dir, 'optics_si_settings.json')
    clicommon.run_command(['rm', '-f', file_path])
    

# place holders for 'sniff prm enable/disable' and 'sniffer all enable/disable'
# @sniffer.command()
# @click.argument('option', type=click.Choice(["enable", "disable"]))
# def prf():
#     pass
#
#
# @sniffer.command()
# @click.argument('option', type=click.Choice(["enable", "disable"]))
# def all():
#     pass


def register(cli):
    version_info = device_info.get_sonic_version_info()
    if (version_info and version_info.get('asic_type') == 'mellanox'):
        cli.commands['platform'].add_command(mlnx)

if __name__ == '__main__':
    sniffer()
