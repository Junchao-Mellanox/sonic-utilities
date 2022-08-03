import click

import tabulate
from natsort import natsorted

import utilities_common.cli as clicommon


FEATURE_TABLE = "FEATURE"
SYSLOG_CONFIG_TABLE = 'SYSLOG_CONFIG'
SYSLOG_CONFIG_FEATURE_TABLE = 'SYSLOG_CONFIG_FEATURE'
SYSLOG_TABLE = "SYSLOG_SERVER"

SYSLOG_SOURCE = "source"
SYSLOG_PORT = "port"
SYSLOG_VRF = "vrf"

SYSLOG_CONFIG_GLOBAL_KEY = 'GLOBAL'
SYSLOG_RATE_LIMIT_INTERVAL = 'rate_limit_interval'
SYSLOG_RATE_LIMIT_BURST = 'rate_limit_burst'

#
# Syslog helpers ------------------------------------------------------------------------------------------------------
#

def format(header, body):
    return tabulate.tabulate(body, header, tablefmt="simple", numalign="left", stralign="left")

#
# Syslog CLI ----------------------------------------------------------------------------------------------------------
#

@click.group(
    name='syslog',
    cls=clicommon.AliasedGroup,
    invoke_without_command=True
)
@click.pass_context
@clicommon.pass_db
def syslog(db, ctx):
    """ Show syslog server configuration """

    if ctx.invoked_subcommand is not None:
        return

    header = [
        "SERVER IP",
        "SOURCE IP",
        "PORT",
        "VRF",
    ]
    body = []

    table = db.cfgdb.get_table(SYSLOG_TABLE)
    for key in natsorted(table):
        entry = table[key]
        row = [key] + [
            entry.get(SYSLOG_SOURCE, "N/A"),
            entry.get(SYSLOG_PORT, "N/A"),
            entry.get(SYSLOG_VRF, "N/A"),
        ]
        body.append(row)

    click.echo(format(header, body))

@syslog.command(
    name='rate-limit-host'
)
@clicommon.pass_db
def rate_limit_host(db):
    """ Show syslog rate limit configuration for host """

    header = [
        "INTERVAL",
        "BURST",
    ]
    body = []
    syslog_configs = db.cfgdb.get_table(SYSLOG_CONFIG_TABLE)
    if SYSLOG_CONFIG_GLOBAL_KEY in syslog_configs:
        entry = syslog_configs[SYSLOG_CONFIG_GLOBAL_KEY]
        body.append([entry.get(SYSLOG_RATE_LIMIT_INTERVAL, 'N/A'),
                    entry.get(SYSLOG_RATE_LIMIT_BURST, 'N/A')])

    click.echo(format(header, body))


@syslog.command(
    name='rate-limit-container'
)
@click.argument('service_name', metavar='<service_name>', required=False)
@clicommon.pass_db
def rate_limit_container(db, service_name):
    """ Show syslog rate limit configuration for containers """

    header = [
        "SERVICE",
        "INTERVAL",
        "BURST",
    ]
    body = []
    features = db.cfgdb.get_table(FEATURE_TABLE)
    syslog_configs = db.cfgdb.get_table(SYSLOG_CONFIG_FEATURE_TABLE)

    if service_name:
        if service_name not in features:
            raise click.UsageError('Invalid service name {}, please choose from: {}'.format(service_name, ','.join(features.keys())))

        state = features[service_name].get('state')
        if state in ['disabled', 'always_disabled']:
            raise click.ClickException('Service {} is disabled, please enable it first'.format(service_name, ))

        support_rate_limit = features[service_name].get('support_syslog_rate_limit', '').lower() == 'true'
        if not support_rate_limit:
            raise click.ClickException('Service {} does not support syslog rate limit'.format(service_name))

        service_list = [service_name]
    else:
        service_list = [name for name, service_config in features.items() if service_config.get('support_syslog_rate_limit', '').lower() == 'true' and \
                                                                             service_config.get('state') not in ['disabled', 'always_disabled']]

    for service in natsorted(service_list):
        if service in syslog_configs:
            entry = syslog_configs[service]
            body.append([service,
                        entry.get(SYSLOG_RATE_LIMIT_INTERVAL, 'N/A'),
                        entry.get(SYSLOG_RATE_LIMIT_BURST, 'N/A')])
        else:
            body.append([service, 'N/A', 'N/A'])

    click.echo(format(header, body))
