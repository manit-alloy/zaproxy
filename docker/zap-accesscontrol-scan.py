#!/usr/bin/env python

# Sample docs here
#

import getopt
import yaml
from pathlib import Path
from shutil import copyfile

from zapv2 import ZAPv2
from zap_common import *

config_dict = {}
config_msg = {}
out_of_scope_dict = {}
min_level = 0


def usage():
    # TO BE FILLED IN
    print('USAGE TBD')
    pass


def main(argv):
    global min_level
    global in_progress_issues
    cid = ''
    context_file = ''
    progress_file = ''
    config_file = ''
    config_url = ''
    generate = ''
    mins = 1
    port = 0
    detailed_output = True
    report_html = ''
    report_md = ''
    report_xml = ''
    report_json = ''
    target = ''
    zap_alpha = False
    info_unspecified = False
    ajax = False
    base_dir = ''
    zap_ip = 'localhost'
    zap_options = ''
    delay = 0
    timeout = 0
    ignore_warn = False
    hook_file = ''
    user = ''
    use_af = False
    af_supported = False
    af_override = False

    pass_count = 0
    warn_count = 0
    fail_count = 0
    info_count = 0
    ignore_count = 0
    warn_inprog_count = 0
    fail_inprog_count = 0
    exception_raised = False
    debug = False

    try:
        opts, args = getopt.getopt(argv, "t:c:u:g:m:n:r:J:w:x:l:hdaijp:sz:P:D:T:IU:", [
                                   "hook=", "auto", "autooff"])
    except getopt.GetoptError as exc:
        logging.warning('Invalid option ' + exc.opt + ' : ' + exc.msg)
        usage()
        sys.exit(3)

    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit(0)
        elif opt == '-t':
            target = arg
            logging.debug('Target: ' + target)
        elif opt == '-c':
            config_file = arg
        elif opt == '-u':
            config_url = arg
        elif opt == '-g':
            generate = arg
            af_supported = False
        elif opt == '-d':
            logging.getLogger().setLevel(logging.DEBUG)
            debug = True
        elif opt == '-m':
            mins = int(arg)
        elif opt == '-P':
            port = int(arg)
        elif opt == '-D':
            delay = int(arg)
            af_supported = False
        elif opt == '-n':
            context_file = arg
            af_supported = False
        elif opt == '-p':
            progress_file = arg
            af_supported = False
        elif opt == '-r':
            report_html = arg
        elif opt == '-J':
            report_json = arg
        elif opt == '-w':
            report_md = arg
        elif opt == '-x':
            report_xml = arg
        elif opt == '-a':
            zap_alpha = True
        elif opt == '-i':
            info_unspecified = True
            af_supported = False
        elif opt == '-I':
            ignore_warn = True
        elif opt == '-j':
            ajax = True
        elif opt == '-l':
            try:
                min_level = zap_conf_lvls.index(arg)
            except ValueError:
                logging.warning('Level must be one of ' + str(zap_conf_lvls))
                usage()
                sys.exit(3)
            af_supported = False
        elif opt == '-z':
            zap_options = arg
        elif opt == '-s':
            detailed_output = False
        elif opt == '-T':
            timeout = int(arg)
        elif opt == '-U':
            user = arg
            af_supported = False
        elif opt == '--hook':
            hook_file = arg
            af_supported = False
        elif opt == '--auto':
            use_af = True
            af_override = True
        elif opt == '--autooff':
            use_af = False

    check_zap_client_version()

    load_custom_hooks(hook_file)
    trigger_hook('cli_opts', opts)

    if running_in_docker():
        base_dir = '/zap/wrk/'
        if config_file or generate or report_html or report_xml or report_json or report_md or progress_file or context_file:
            # Check directory has been mounted
            if not os.path.exists(base_dir):
                logging.warning(
                    'A file based option has been specified but the directory \'/zap/wrk\' is not mounted ')
                usage()
                sys.exit(3)

    if user and not context_file:
        logging.warning(
            'A context file must be specified (and include the user) if the user option is selected')
        usage()
        sys.exit(3)

    # Choose a random 'ephemeral' port and check its available if it wasn't specified with -P option
    if port == 0:
        port = get_free_port()

    logging.debug('Using port: ' + str(port))

    if config_file:
        # load config file from filestore
        config_file = os.path.join(base_dir, config_file)
        with open(config_file) as f:
            try:
                load_config(f, config_dict, config_msg, out_of_scope_dict)
            except ValueError as e:
                logging.warning("Failed to load config file " +
                                config_file + " " + str(e))
                sys.exit(3)
    elif config_url:
        # load config file from url
        try:
            config_data = urlopen(config_url).read().decode(
                'UTF-8').splitlines()
            load_config(config_data, config_dict,
                        config_msg, out_of_scope_dict)
        except ValueError as e:
            logging.warning("Failed to read configs from " +
                            config_url + " " + str(e))
            sys.exit(3)
        except:
            logging.warning('Failed to read configs from ' + config_url)
            sys.exit(3)

    if progress_file:
        # load progress file from filestore
        with open(os.path.join(base_dir, progress_file)) as f:
            progress = json.load(f)
            # parse into something more useful...
            # in_prog_issues = map of vulnid -> {object with everything in}
            for issue in progress["issues"]:
                if issue["state"] == "inprogress":
                    in_progress_issues[issue["id"]] = issue

    if running_in_docker():
        if use_af and af_supported:
            print('Using the Automation Framework')

            # Generate the yaml file
            home_dir = str(Path.home())
            yaml_file = os.path.join(home_dir, 'zap.yaml')
            summary_file = os.path.join(home_dir, 'zap_out.json')

            with open(yaml_file, 'w') as yf:

                # Add the top level to the scope for backwards compatibility
                top_levels = [target]
                if target.count('/') > 2:
                    # The url can include a valid path, but always reset to spider the host (backwards compatibility)
                    t2 = target[0:target.index('/', 8)+1]
                    if not t2 == target:
                        target = t2
                        top_levels.append(target)

                yaml.dump(get_af_env(top_levels, out_of_scope_dict, debug), yf)

                alertFilters = []

                # Handle id specific alertFilters - rules that apply to all IDs are excluded from the env
                for id in out_of_scope_dict:
                    if id != '*':
                        for regex in out_of_scope_dict[id]:
                            alertFilters.append(
                                {'ruleId': id, 'newRisk': 'False Positive', 'url': regex.pattern, 'urlRegex': True})

                jobs = [get_af_pscan_config()]

                if len(alertFilters) > 0:
                    jobs.append(get_af_alertFilter(alertFilters))

                jobs.append(get_af_spider(target, mins))

                if ajax:
                    jobs.append(get_af_spiderAjax(target, mins))

                jobs.append(get_af_pscan_wait(timeout))
                jobs.append(get_af_output_summary(('Short', 'Long')[
                            detailed_output], summary_file, config_dict, config_msg))

                if report_html:
                    jobs.append(get_af_report(
                        'traditional-html', base_dir, report_html, 'ZAP Scanning Report', ''))

                if report_md:
                    jobs.append(get_af_report('traditional-md',
                                base_dir, report_md, 'ZAP Scanning Report', ''))

                if report_xml:
                    jobs.append(get_af_report('traditional-xml',
                                base_dir, report_xml, 'ZAP Scanning Report', ''))

                if report_json:
                    jobs.append(get_af_report(
                        'traditional-json', base_dir, report_json, 'ZAP Scanning Report', ''))

                yaml.dump({'jobs': jobs}, yf)

                if os.path.exists('/zap/wrk'):
                    yaml_copy_file = '/zap/wrk/zap.yaml'
                    try:
                        # Write the yaml file to the mapped directory, if there is one
                        copyfile(yaml_file, yaml_copy_file)
                    except OSError as err:
                        logging.warning(
                            'Unable to copy yaml file to ' + yaml_copy_file + ' ' + str(err))

            try:
                # Run ZAP inline to update the add-ons
                install_opts = ['-addonupdate',
                                '-addoninstall', 'pscanrulesBeta']
                if zap_alpha:
                    install_opts.append('-addoninstall')
                    install_opts.append('pscanrulesAlpha')

                run_zap_inline(port, install_opts)

                # Run ZAP inline with the yaml file
                params = ['-autorun', yaml_file]

                add_zap_options(params, zap_options)

                out = run_zap_inline(port, params)

                ignore_strs = ["Found Java version", "Available memory", "Using JVM args", "Add-on already installed", "[main] INFO",
                               "Automation plan succeeded"]

                for line in out.splitlines():
                    if any(x in line for x in ignore_strs):
                        continue
                    print(line)

            except OSError:
                logging.warning('Failed to start ZAP :(')
                sys.exit(3)

            # Read the status file to find out what code we should exit with
            if not os.path.isfile(summary_file):
                logging.warning(
                    'Failed to access summary file ' + summary_file)
                sys.exit(3)

            try:
                with open(summary_file) as f:
                    summary_data = json.load(f)

                    if summary_data['fail'] > 0:
                        sys.exit(1)
                    elif (not ignore_warn) and summary_data['warn'] > 0:
                        sys.exit(2)
                    elif summary_data['pass'] > 0:
                        sys.exit(0)
                    else:
                        sys.exit(3)
            except IOError:
                logging.warning('Failed to read summary file ' + summary_file)

            sys.exit(3)

        else:
            try:
                params = [
                    '-config', 'spider.maxDuration=' + str(mins),
                    '-addonupdate',
                    '-addoninstall', 'pscanrulesBeta']  # In case we're running in the stable container

                if zap_alpha:
                    params.append('-addoninstall')
                    params.append('pscanrulesAlpha')

                add_zap_options(params, zap_options)

                start_zap(port, params)

            except OSError:
                logging.warning('Failed to start ZAP :(')
                sys.exit(3)

    else:
        # Not running in docker, so start one
        mount_dir = ''
        if context_file:
            mount_dir = os.path.dirname(os.path.abspath(context_file))

        params = [
            '-config', 'spider.maxDuration=' + str(mins),
            '-addonupdate']

        if (zap_alpha):
            params.extend(['-addoninstall', 'pscanrulesAlpha'])

        add_zap_options(params, zap_options)

        try:
            cid = start_docker_zap(
                'owasp/zap2docker-weekly', port, params, mount_dir)
            zap_ip = ipaddress_for_cid(cid)
            logging.debug('Docker ZAP IP Addr: ' + zap_ip)
        except OSError:
            logging.warning('Failed to start ZAP in docker :(')
            sys.exit(3)

    ### END OF COMMON CODE FOR COMMANDS ####

    try:
        zap = ZAPv2(proxies={'http': 'http://' + zap_ip + ':' +
                    str(port), 'https': 'http://' + zap_ip + ':' + str(port)})

        wait_for_zap_start(zap, timeout * 60)
        trigger_hook('zap_started', zap, target)

        # Make suitable performance tweaks for running in this environment
        zap_tune(zap)
        trigger_hook('zap_tuned', zap)

        if context_file:
            # handle the context file, cant use base_dir as it might not have been set up
            zap_import_context(zap, os.path.join('/zap/wrk/', context_file))
            if (user):
                zap_set_scan_user(zap, user)

        zap_access_target(zap, target)

        report_filename = os.path.join('/zap/wrk', report_html)
        zap_accesscontrol_scan(zap, report_filename)

        trigger_hook('zap_pre_shutdown', zap)
        # Stop ZAP
        zap.core.shutdown()
    except UserInputException as e:
        exception_raised = True
        print("ERROR %s" % e)

    except ScanNotStartedException:
        exception_raised = True
        dump_log_file(cid)

    except IOError as e:
        exception_raised = True
        print("ERROR %s" % e)
        logging.warning('I/O error: ' + str(e))
        dump_log_file(cid)

    except:
        exception_raised = True
        print("ERROR " + str(sys.exc_info()[0]))
        logging.warning('Unexpected error: ' + str(sys.exc_info()[0]))
        dump_log_file(cid)

    if not running_in_docker():
        stop_docker(cid)

    trigger_hook('pre_exit', fail_count, warn_count, pass_count)

    if exception_raised:
        sys.exit(3)
    elif fail_count > 0:
        sys.exit(1)
    elif (not ignore_warn) and warn_count > 0:
        sys.exit(2)
    elif pass_count > 0:
        sys.exit(0)
    else:
        sys.exit(3)


if __name__ == "__main__":
    main(sys.argv[1:])
