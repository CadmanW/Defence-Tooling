//! Integration-tests for the Rhai rule engine
//! (lives in `tests/engine.rs`, so it is compiled as a
//! separate crate that depends on `flying_ace_engine`)
#[cfg(test)]
mod tests {
    use flying_ace_engine::rule_fixtures::{
        base_event, event_from_test_case, load_rule_fixture, load_rule_fixtures,
    };
    use flying_ace_engine::{EcsRhaiEngine, RuleMode};

    /// Convenience helper – the engine always loads rules from `rules/`
    fn new_engine() -> EcsRhaiEngine {
        EcsRhaiEngine::new_from_dir("rules")
    }

    /// Run all embedded tests for a single YAML rule file.
    fn run_rule_yaml(yaml_file: &str) {
        let path = std::path::Path::new("rules").join(yaml_file);
        let rule = load_rule_fixture(&path)
            .unwrap_or_else(|e| panic!("{}: failed to deserialize: {}", path.display(), e));

        assert!(
            !rule.tests.is_empty(),
            "rule '{}' in {} has no embedded tests",
            rule.name,
            path.display()
        );

        let engine = EcsRhaiEngine::new_from_dir(path.parent().unwrap());

        for (i, tc) in rule.tests.iter().enumerate() {
            let event = event_from_test_case(tc);
            let matches = engine.eval(&event);
            let did_match = matches.iter().any(|m| m.name == rule.name);

            assert_eq!(
                did_match, tc.should_match,
                "\nrule='{}' test[{}] cleartext='{}'\n  process_name='{}' process_args={:?}\n",
                rule.name, i, tc.cleartext, event.process_name, event.process_args,
            );
        }
    }

    // One #[test] per rule YAML - each shows up individually in `cargo test`

    macro_rules! rule_test {
        ($test_name:ident, $yaml_file:expr) => {
            #[test]
            fn $test_name() {
                run_rule_yaml($yaml_file);
            }
        };
    }

    // XXX: this is kinda gross to list every rule like this, clean it up with some auto discovery
    // at some point
    rule_test!(rule_ansible_usage, "original/ansible.yaml");
    rule_test!(rule_wall_usage, "original/wall.yaml");
    rule_test!(rule_curl_wget_download, "original/curl_wget_download.yaml");
    rule_test!(rule_curl_pipe_bash, "original/curl_pipe_bash.yaml");
    rule_test!(rule_webserver_shell_spawn, "original/webserver_shell.yaml");
    rule_test!(rule_python_reverse_shell, "original/python_revshell.yaml");
    rule_test!(rule_root_ssh_login, "original/root_ssh_login.yaml");
    rule_test!(rule_process_from_memory, "original/process_from_mem.yaml");
    rule_test!(rule_compilation_detected, "original/compilation.yaml");
    rule_test!(rule_dd_usage, "original/dd_usage.yaml");
    rule_test!(
        rule_rm_rf_no_preserve_root,
        "original/rm_rf_nopreserve.yaml"
    );
    rule_test!(
        rule_linux_hack_tool_frameworks,
        "original/linux_hack_tool_frameworks.yaml"
    );
    rule_test!(
        rule_linux_hack_tool_recon,
        "original/linux_hack_tool_recon.yaml"
    );
    rule_test!(
        rule_linux_hack_tool_scripts,
        "original/linux_hack_tool_scripts.yaml"
    );
    rule_test!(rule_histfile_removal, "original/histfile_removal.yaml");
    rule_test!(rule_interact_lkm, "original/interact_lkm.yaml");
    rule_test!(rule_rta_ld_preload_hijack, "rta/rta_ld_preload_hijack.yaml");
    rule_test!(rule_rta_packet_capture, "rta/rta_packet_capture.yaml");
    rule_test!(rule_rta_dns_exfiltration, "rta/rta_dns_exfiltration.yaml");
    rule_test!(rule_rta_wget_post_exfil, "rta/rta_wget_post_exfil.yaml");
    rule_test!(rule_rta_history_tampering, "rta/rta_history_tampering.yaml");
    rule_test!(
        rule_rta_packed_binary_exec,
        "rta/rta_packed_binary_exec.yaml"
    );
    rule_test!(
        rule_rta_rc_script_persistence,
        "rta/rta_rc_script_persistence.yaml"
    );
    rule_test!(
        rule_rta_systemd_timer_persistence,
        "rta/rta_systemd_timer_persistence.yaml"
    );
    rule_test!(rule_rta_ssh_remote_exfil, "rta/rta_ssh_remote_exfil.yaml");
    rule_test!(rule_rta_mimipenguin, "rta/rta_mimipenguin.yaml");
    rule_test!(rule_rta_useradd, "rta/rta_useradd.yaml");
    rule_test!(rule_rta_passwd_change, "rta/rta_passwd_change.yaml");
    rule_test!(rule_rta_sshpass_usage, "rta/rta_sshpass_usage.yaml");
    rule_test!(
        rule_rta_data_staging_split,
        "rta/rta_data_staging_split.yaml"
    );
    rule_test!(rule_rta_background_shell, "rta/rta_background_shell.yaml");
    rule_test!(
        rule_rta_bash_dev_tcp_reverse_shell,
        "rta/rta_bash_dev_tcp_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_sudo_cve_2019_14287,
        "rta/rta_sudo_cve_2019_14287.yaml"
    );
    rule_test!(
        rule_rta_docker_container_escape,
        "rta/rta_docker_container_escape.yaml"
    );
    rule_test!(
        rule_rta_mkfifo_reverse_shell_chain,
        "rta/rta_mkfifo_reverse_shell_chain.yaml"
    );
    rule_test!(
        rule_rta_dd_proc_mem_injection,
        "rta/rta_dd_proc_mem_injection.yaml"
    );
    rule_test!(
        rule_rta_socat_reverse_shell,
        "rta/rta_socat_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_openssl_reverse_shell,
        "rta/rta_openssl_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_perl_socket_reverse_shell,
        "rta/rta_perl_socket_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_php_cli_reverse_shell,
        "rta/rta_php_cli_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_nodejs_reverse_shell,
        "rta/rta_nodejs_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_ruby_socket_reverse_shell,
        "rta/rta_ruby_socket_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_less_more_shell_escape,
        "rta/rta_less_more_shell_escape.yaml"
    );
    rule_test!(rule_rta_find_exec_shell, "rta/rta_find_exec_shell.yaml");
    rule_test!(rule_rta_awk_system_shell, "rta/rta_awk_system_shell.yaml");
    rule_test!(
        rule_rta_lxd_container_escape,
        "rta/rta_lxd_container_escape.yaml"
    );
    rule_test!(
        rule_rta_capabilities_abuse,
        "rta/rta_capabilities_abuse.yaml"
    );
    rule_test!(
        rule_rta_base64_decode_to_exec,
        "rta/rta_base64_decode_to_exec.yaml"
    );
    rule_test!(
        rule_rta_system_log_truncation,
        "rta/rta_system_log_truncation.yaml"
    );
    rule_test!(
        rule_rta_log_overwrite_devnull,
        "rta/rta_log_overwrite_devnull.yaml"
    );
    rule_test!(
        rule_rta_gdb_process_attach_injection,
        "rta/rta_gdb_process_attach_injection.yaml"
    );
    rule_test!(
        rule_rta_ptrace_process_injection,
        "rta/rta_ptrace_process_injection.yaml"
    );
    rule_test!(
        rule_rta_telnet_reverse_shell,
        "rta/rta_telnet_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_curl_telnet_reverse_shell,
        "rta/rta_curl_telnet_reverse_shell.yaml"
    );
    rule_test!(
        rule_rta_awk_inet_tcp_shell,
        "rta/rta_awk_inet_tcp_shell.yaml"
    );
    rule_test!(rule_rta_man_shell_escape, "rta/rta_man_shell_escape.yaml");
    rule_test!(
        rule_rta_sed_shell_execution,
        "rta/rta_sed_shell_execution.yaml"
    );
    rule_test!(
        rule_rta_ldap_user_enumeration,
        "rta/rta_ldap_user_enumeration.yaml"
    );
    rule_test!(
        rule_rta_ldap_group_enumeration,
        "rta/rta_ldap_group_enumeration.yaml"
    );
    rule_test!(
        rule_rta_xxd_hex_decode_exec,
        "rta/rta_xxd_hex_decode_exec.yaml"
    );
    rule_test!(
        rule_rta_suid_binary_enumeration,
        "rta/rta_suid_binary_enumeration.yaml"
    );
    rule_test!(
        rule_rta_history_tampering_enhanced,
        "rta/rta_history_tampering_enhanced.yaml"
    );
    rule_test!(rule_rta_shred_log_files, "rta/rta_shred_log_files.yaml");
    rule_test!(
        rule_rta_journalctl_log_deletion,
        "rta/rta_journalctl_log_deletion.yaml"
    );
    rule_test!(
        rule_rta_lua_socket_reverse_shell,
        "rta/rta_lua_socket_reverse_shell.yaml"
    );
    rule_test!(rule_rta_ed_shell_escape, "rta/rta_ed_shell_escape.yaml");
    rule_test!(
        rule_rta_od_octal_dump_sensitive_files,
        "rta/rta_od_octal_dump_sensitive_files.yaml"
    );

    // Sigma rules
    rule_test!(
        rule_sigma_apt_shell_execution,
        "sigma/sigma_apt_shell_execution.yaml"
    );
    rule_test!(rule_sigma_at_command, "sigma/sigma_at_command.yaml");
    rule_test!(
        rule_sigma_auditctl_clear_rules,
        "sigma/sigma_auditctl_clear_rules.yaml"
    );
    rule_test!(
        rule_sigma_av_kaspersky_av_disabled,
        "sigma/sigma_av_kaspersky_av_disabled.yaml"
    );
    rule_test!(
        rule_sigma_awk_shell_spawn,
        "sigma/sigma_awk_shell_spawn.yaml"
    );
    rule_test!(rule_sigma_base64_decode, "sigma/sigma_base64_decode.yaml");
    rule_test!(
        rule_sigma_base64_execution,
        "sigma/sigma_base64_execution.yaml"
    );
    rule_test!(
        rule_sigma_base64_shebang_cli,
        "sigma/sigma_base64_shebang_cli.yaml"
    );
    rule_test!(
        rule_sigma_bash_interactive_shell,
        "sigma/sigma_bash_interactive_shell.yaml"
    );
    rule_test!(
        rule_sigma_bpf_kprob_tracing_enabled,
        "sigma/sigma_bpf_kprob_tracing_enabled.yaml"
    );
    rule_test!(
        rule_sigma_bpftrace_unsafe_option_usage,
        "sigma/sigma_bpftrace_unsafe_option_usage.yaml"
    );
    rule_test!(rule_sigma_cap_setgid, "sigma/sigma_cap_setgid.yaml");
    rule_test!(rule_sigma_cap_setuid, "sigma/sigma_cap_setuid.yaml");
    rule_test!(rule_sigma_capa_discovery, "sigma/sigma_capa_discovery.yaml");
    rule_test!(
        rule_sigma_capsh_shell_invocation,
        "sigma/sigma_capsh_shell_invocation.yaml"
    );
    rule_test!(
        rule_sigma_chattr_immutable_removal,
        "sigma/sigma_chattr_immutable_removal.yaml"
    );
    rule_test!(
        rule_sigma_chroot_execution,
        "sigma/sigma_chroot_execution.yaml"
    );
    rule_test!(rule_sigma_clear_logs, "sigma/sigma_clear_logs.yaml");
    rule_test!(rule_sigma_clear_syslog, "sigma/sigma_clear_syslog.yaml");
    rule_test!(
        rule_sigma_clipboard_collection,
        "sigma/sigma_clipboard_collection.yaml"
    );
    rule_test!(
        rule_sigma_cp_passwd_or_shadow_tmp,
        "sigma/sigma_cp_passwd_or_shadow_tmp.yaml"
    );
    rule_test!(
        rule_sigma_crontab_enumeration,
        "sigma/sigma_crontab_enumeration.yaml"
    );
    rule_test!(
        rule_sigma_crontab_removal,
        "sigma/sigma_crontab_removal.yaml"
    );
    rule_test!(rule_sigma_curl_usage, "sigma/sigma_curl_usage.yaml");
    rule_test!(
        rule_sigma_curl_wget_exec_tmp,
        "sigma/sigma_curl_wget_exec_tmp.yaml"
    );
    rule_test!(
        rule_sigma_dd_file_overwrite,
        "sigma/sigma_dd_file_overwrite.yaml"
    );
    rule_test!(
        rule_sigma_dd_process_injection,
        "sigma/sigma_dd_process_injection.yaml"
    );
    rule_test!(rule_sigma_disable_ufw, "sigma/sigma_disable_ufw.yaml");
    rule_test!(rule_sigma_doas_execution, "sigma/sigma_doas_execution.yaml");
    rule_test!(
        rule_sigma_env_shell_invocation,
        "sigma/sigma_env_shell_invocation.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_network_discovery,
        "sigma/sigma_esxcli_network_discovery.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_permission_change_admin,
        "sigma/sigma_esxcli_permission_change_admin.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_storage_discovery,
        "sigma/sigma_esxcli_storage_discovery.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_syslog_config_change,
        "sigma/sigma_esxcli_syslog_config_change.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_system_discovery,
        "sigma/sigma_esxcli_system_discovery.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_user_account_creation,
        "sigma/sigma_esxcli_user_account_creation.yaml"
    );
    rule_test!(
        rule_sigma_esxcli_vm_discovery,
        "sigma/sigma_esxcli_vm_discovery.yaml"
    );
    rule_test!(rule_sigma_esxcli_vm_kill, "sigma/sigma_esxcli_vm_kill.yaml");
    rule_test!(
        rule_sigma_esxcli_vsan_discovery,
        "sigma/sigma_esxcli_vsan_discovery.yaml"
    );
    rule_test!(rule_sigma_file_deletion, "sigma/sigma_file_deletion.yaml");
    rule_test!(
        rule_sigma_find_shell_execution,
        "sigma/sigma_find_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_flock_shell_execution,
        "sigma/sigma_flock_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_gcc_shell_execution,
        "sigma/sigma_gcc_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_git_shell_execution,
        "sigma/sigma_git_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_grep_os_arch_discovery,
        "sigma/sigma_grep_os_arch_discovery.yaml"
    );
    rule_test!(rule_sigma_groupdel, "sigma/sigma_groupdel.yaml");
    rule_test!(
        rule_sigma_install_root_certificate,
        "sigma/sigma_install_root_certificate.yaml"
    );
    rule_test!(
        rule_sigma_install_suspicious_packages,
        "sigma/sigma_install_suspicious_packages.yaml"
    );
    rule_test!(
        rule_sigma_iptables_flush_ufw,
        "sigma/sigma_iptables_flush_ufw.yaml"
    );
    rule_test!(rule_sigma_local_account, "sigma/sigma_local_account.yaml");
    rule_test!(rule_sigma_local_groups, "sigma/sigma_local_groups.yaml");
    rule_test!(
        rule_sigma_malware_gobrat_grep_payload_discovery,
        "sigma/sigma_malware_gobrat_grep_payload_discovery.yaml"
    );
    rule_test!(
        rule_sigma_mkfifo_named_pipe_creation,
        "sigma/sigma_mkfifo_named_pipe_creation.yaml"
    );
    rule_test!(
        rule_sigma_mkfifo_named_pipe_creation_susp_location,
        "sigma/sigma_mkfifo_named_pipe_creation_susp_location.yaml"
    );
    rule_test!(rule_sigma_mount_hidepid, "sigma/sigma_mount_hidepid.yaml");
    rule_test!(
        rule_sigma_netcat_reverse_shell,
        "sigma/sigma_netcat_reverse_shell.yaml"
    );
    rule_test!(
        rule_sigma_nice_shell_execution,
        "sigma/sigma_nice_shell_execution.yaml"
    );
    rule_test!(rule_sigma_nohup, "sigma/sigma_nohup.yaml");
    rule_test!(
        rule_sigma_nohup_susp_execution,
        "sigma/sigma_nohup_susp_execution.yaml"
    );
    rule_test!(
        rule_sigma_omigod_scx_runasprovider_executescript,
        "sigma/sigma_omigod_scx_runasprovider_executescript.yaml"
    );
    rule_test!(
        rule_sigma_omigod_scx_runasprovider_executeshellcommand,
        "sigma/sigma_omigod_scx_runasprovider_executeshellcommand.yaml"
    );
    rule_test!(
        rule_sigma_perl_reverse_shell,
        "sigma/sigma_perl_reverse_shell.yaml"
    );
    rule_test!(
        rule_sigma_php_reverse_shell,
        "sigma/sigma_php_reverse_shell.yaml"
    );
    rule_test!(
        rule_sigma_pnscan_binary_cli_pattern,
        "sigma/sigma_pnscan_binary_cli_pattern.yaml"
    );
    rule_test!(
        rule_sigma_proxy_connection,
        "sigma/sigma_proxy_connection.yaml"
    );
    rule_test!(rule_sigma_pua_trufflehog, "sigma/sigma_pua_trufflehog.yaml");
    rule_test!(
        rule_sigma_python_http_server_execution,
        "sigma/sigma_python_http_server_execution.yaml"
    );
    rule_test!(
        rule_sigma_python_pty_spawn,
        "sigma/sigma_python_pty_spawn.yaml"
    );
    rule_test!(
        rule_sigma_python_reverse_shell,
        "sigma/sigma_python_reverse_shell.yaml"
    );
    rule_test!(
        rule_sigma_python_shell_os_system,
        "sigma/sigma_python_shell_os_system.yaml"
    );
    rule_test!(
        rule_sigma_remote_access_tools_teamviewer_incoming_connection,
        "sigma/sigma_remote_access_tools_teamviewer_incoming_connection.yaml"
    );
    rule_test!(
        rule_sigma_remote_system_discovery,
        "sigma/sigma_remote_system_discovery.yaml"
    );
    rule_test!(rule_sigma_remove_package, "sigma/sigma_remove_package.yaml");
    rule_test!(
        rule_sigma_rsync_shell_execution,
        "sigma/sigma_rsync_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_rsync_shell_spawn,
        "sigma/sigma_rsync_shell_spawn.yaml"
    );
    rule_test!(
        rule_sigma_ruby_reverse_shell,
        "sigma/sigma_ruby_reverse_shell.yaml"
    );
    rule_test!(
        rule_sigma_schedule_task_job_cron,
        "sigma/sigma_schedule_task_job_cron.yaml"
    );
    rule_test!(
        rule_sigma_security_software_discovery,
        "sigma/sigma_security_software_discovery.yaml"
    );
    rule_test!(
        rule_sigma_security_tools_disabling,
        "sigma/sigma_security_tools_disabling.yaml"
    );
    rule_test!(
        rule_sigma_services_stop_and_disable,
        "sigma/sigma_services_stop_and_disable.yaml"
    );
    rule_test!(rule_sigma_setgid_setuid, "sigma/sigma_setgid_setuid.yaml");
    rule_test!(
        rule_sigma_ssh_shell_execution,
        "sigma/sigma_ssh_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_ssm_agent_abuse,
        "sigma/sigma_ssm_agent_abuse.yaml"
    );
    rule_test!(
        rule_sigma_susp_chmod_directories,
        "sigma/sigma_susp_chmod_directories.yaml"
    );
    rule_test!(
        rule_sigma_susp_container_residence_discovery,
        "sigma/sigma_susp_container_residence_discovery.yaml"
    );
    rule_test!(
        rule_sigma_susp_curl_fileupload,
        "sigma/sigma_susp_curl_fileupload.yaml"
    );
    rule_test!(
        rule_sigma_susp_curl_useragent,
        "sigma/sigma_susp_curl_useragent.yaml"
    );
    rule_test!(
        rule_sigma_susp_dockerenv_recon,
        "sigma/sigma_susp_dockerenv_recon.yaml"
    );
    rule_test!(
        rule_sigma_susp_execution_tmp_folder,
        "sigma/sigma_susp_execution_tmp_folder.yaml"
    );
    rule_test!(
        rule_sigma_susp_find_execution,
        "sigma/sigma_susp_find_execution.yaml"
    );
    rule_test!(rule_sigma_susp_git_clone, "sigma/sigma_susp_git_clone.yaml");
    rule_test!(
        rule_sigma_susp_history_delete,
        "sigma/sigma_susp_history_delete.yaml"
    );
    rule_test!(
        rule_sigma_susp_history_recon,
        "sigma/sigma_susp_history_recon.yaml"
    );
    rule_test!(
        rule_sigma_susp_hktl_execution,
        "sigma/sigma_susp_hktl_execution.yaml"
    );
    rule_test!(
        rule_sigma_susp_inod_listing,
        "sigma/sigma_susp_inod_listing.yaml"
    );
    rule_test!(
        rule_sigma_susp_interactive_bash,
        "sigma/sigma_susp_interactive_bash.yaml"
    );
    rule_test!(
        rule_sigma_susp_java_children,
        "sigma/sigma_susp_java_children.yaml"
    );
    rule_test!(
        rule_sigma_susp_network_utilities_execution,
        "sigma/sigma_susp_network_utilities_execution.yaml"
    );
    rule_test!(
        rule_sigma_susp_pipe_shell,
        "sigma/sigma_susp_pipe_shell.yaml"
    );
    rule_test!(
        rule_sigma_susp_process_reading_sudoers,
        "sigma/sigma_susp_process_reading_sudoers.yaml"
    );
    rule_test!(
        rule_sigma_susp_recon_indicators,
        "sigma/sigma_susp_recon_indicators.yaml"
    );
    rule_test!(
        rule_sigma_susp_sensitive_file_access,
        "sigma/sigma_susp_sensitive_file_access.yaml"
    );
    rule_test!(
        rule_sigma_susp_shell_child_process_from_parent_tmp_folder,
        "sigma/sigma_susp_shell_child_process_from_parent_tmp_folder.yaml"
    );
    rule_test!(
        rule_sigma_susp_shell_script_exec_from_susp_location,
        "sigma/sigma_susp_shell_script_exec_from_susp_location.yaml"
    );
    rule_test!(
        rule_sigma_system_network_connections_discovery,
        "sigma/sigma_system_network_connections_discovery.yaml"
    );
    rule_test!(
        rule_sigma_system_network_discovery,
        "sigma/sigma_system_network_discovery.yaml"
    );
    rule_test!(
        rule_sigma_systemctl_mask_power_settings,
        "sigma/sigma_systemctl_mask_power_settings.yaml"
    );
    rule_test!(rule_sigma_touch_susp, "sigma/sigma_touch_susp.yaml");
    rule_test!(
        rule_sigma_triple_cross_rootkit_execve_hijack,
        "sigma/sigma_triple_cross_rootkit_execve_hijack.yaml"
    );
    rule_test!(
        rule_sigma_triple_cross_rootkit_install,
        "sigma/sigma_triple_cross_rootkit_install.yaml"
    );
    rule_test!(rule_sigma_userdel, "sigma/sigma_userdel.yaml");
    rule_test!(
        rule_sigma_usermod_susp_group,
        "sigma/sigma_usermod_susp_group.yaml"
    );
    rule_test!(
        rule_sigma_vim_shell_execution,
        "sigma/sigma_vim_shell_execution.yaml"
    );
    rule_test!(
        rule_sigma_webshell_detection,
        "sigma/sigma_webshell_detection.yaml"
    );
    rule_test!(
        rule_sigma_wget_download_suspicious_directory,
        "sigma/sigma_wget_download_suspicious_directory.yaml"
    );
    rule_test!(
        rule_sigma_xterm_reverse_shell,
        "sigma/sigma_xterm_reverse_shell.yaml"
    );

    // --- unit test rules ---
    rule_test!(rule_unit_test_1, "unit_tests/unit_test_1.yaml");
    rule_test!(rule_unit_test_4, "unit_tests/unit_test_4.yaml");
    rule_test!(rule_unit_test_6, "unit_tests/unit_test_6.yaml");
    rule_test!(rule_unit_test_7, "unit_tests/unit_test_7.yaml");

    // --- elastic-inspired rules ---
    rule_test!(
        rule_elastic_chisel_tunneling,
        "elastic/elastic_chisel_tunneling.yaml"
    );
    rule_test!(
        rule_elastic_k8s_service_account_access,
        "elastic/elastic_k8s_service_account_access.yaml"
    );
    rule_test!(
        rule_elastic_bpftool_tampering,
        "elastic/elastic_bpftool_tampering.yaml"
    );
    rule_test!(
        rule_elastic_earthworm_tunneling,
        "elastic/elastic_earthworm_tunneling.yaml"
    );
    rule_test!(
        rule_elastic_kubectl_impersonation,
        "elastic/elastic_kubectl_impersonation.yaml"
    );
    rule_test!(
        rule_elastic_docker_socket_discovery,
        "elastic/elastic_docker_socket_discovery.yaml"
    );
    rule_test!(
        rule_elastic_kubeconfig_discovery,
        "elastic/elastic_kubeconfig_discovery.yaml"
    );
    rule_test!(
        rule_elastic_container_management_binary,
        "elastic/elastic_container_management_binary.yaml"
    );
    rule_test!(
        rule_elastic_proxychains_activity,
        "elastic/elastic_proxychains_activity.yaml"
    );
    rule_test!(
        rule_elastic_ssh_x11_forwarding,
        "elastic/elastic_ssh_x11_forwarding.yaml"
    );
    rule_test!(
        rule_elastic_aws_creds_container_search,
        "elastic/elastic_aws_creds_container_search.yaml"
    );
    rule_test!(
        rule_elastic_kubectl_api_direct_request,
        "elastic/elastic_kubectl_api_direct_request.yaml"
    );
    rule_test!(
        rule_elastic_telegram_api_exfil,
        "elastic/elastic_telegram_api_exfil.yaml"
    );
    rule_test!(
        rule_elastic_ip_forwarding_enable,
        "elastic/elastic_ip_forwarding_enable.yaml"
    );
    rule_test!(
        rule_elastic_proot_container_escape,
        "elastic/elastic_proot_container_escape.yaml"
    );
    rule_test!(
        rule_elastic_bpf_persistence,
        "elastic/elastic_bpf_persistence.yaml"
    );
    rule_test!(
        rule_elastic_cups_foomatic_rip_shell,
        "elastic/elastic_cups_foomatic_rip_shell.yaml"
    );
    rule_test!(
        rule_elastic_kernel_module_load,
        "elastic/elastic_kernel_module_load.yaml"
    );
    rule_test!(
        rule_elastic_sudo_ld_preload,
        "elastic/elastic_sudo_ld_preload.yaml"
    );
    rule_test!(
        rule_elastic_pam_module_creation,
        "elastic/elastic_pam_module_creation.yaml"
    );
    rule_test!(
        rule_elastic_motd_persistence,
        "elastic/elastic_motd_persistence.yaml"
    );
    rule_test!(
        rule_elastic_rc_local_persistence,
        "elastic/elastic_rc_local_persistence.yaml"
    );
    rule_test!(
        rule_elastic_gdb_process_injection,
        "elastic/elastic_gdb_process_injection.yaml"
    );
    rule_test!(
        rule_elastic_pkexec_priv_esc,
        "elastic/elastic_pkexec_priv_esc.yaml"
    );
    rule_test!(
        rule_elastic_apt_hook_persistence,
        "elastic/elastic_apt_hook_persistence.yaml"
    );
    rule_test!(
        rule_elastic_overlayfs_priv_esc,
        "elastic/elastic_overlayfs_priv_esc.yaml"
    );

    // =========================================================================
    // Verify mode parsing works correctly
    // =========================================================================

    #[test]
    fn rule_mode_defaults_to_alert() {
        let engine = new_engine();
        let mut event = base_event();
        event.process_name = "bash".into();
        event.process_args = Some("bash -c whoami".into());

        let matches = engine.eval(&event);
        for m in &matches {
            if m.name == "bash_c_execution" {
                assert_eq!(
                    m.mode,
                    RuleMode::Alert,
                    "Expected bash_c_execution to default to Alert mode"
                );
            }
        }
    }

    #[test]
    fn smoke_test_rule_overlap_detection() {
        use std::collections::HashMap;

        println!("\n========== RULE OVERLAP DETECTION SMOKE TEST ==========\n");

        let engine = new_engine();

        // Collect all test cases from all YAML files
        let mut all_overlaps: Vec<(String, String, Vec<String>)> = Vec::new();
        let mut total_tests = 0;
        let mut tests_with_overlaps = 0;

        let fixtures = load_rule_fixtures(std::path::Path::new("rules"))
            .expect("failed to load rule fixtures for overlap smoke test");

        println!("Found {} rule files\n", fixtures.len());

        // Process each rule file
        for rule in &fixtures {
            // Test each positive test case (should_match: true)
            for tc in rule.tests.iter() {
                if !tc.should_match {
                    continue;
                }

                total_tests += 1;
                let event = event_from_test_case(tc);
                let matches = engine.eval(&event);

                // Check if multiple rules matched
                if matches.len() > 1 {
                    tests_with_overlaps += 1;
                    let matched_rules: Vec<String> =
                        matches.iter().map(|m| m.name.clone()).collect();
                    all_overlaps.push((rule.name.clone(), tc.cleartext.clone(), matched_rules));
                }
            }
        }

        // Print summary
        println!("========== OVERLAP SUMMARY ==========");
        println!("Total positive test cases: {}", total_tests);
        println!("Test cases with overlaps: {}", tests_with_overlaps);
        println!(
            "Overlap percentage: {:.1}%\n",
            (tests_with_overlaps as f64 / total_tests as f64) * 100.0
        );

        if !all_overlaps.is_empty() {
            println!("========== DETAILED OVERLAPS ==========\n");

            // Group by rule name for better readability
            let mut by_rule: HashMap<String, Vec<(String, Vec<String>)>> = HashMap::new();
            for (rule_name, test_desc, matched_rules) in &all_overlaps {
                by_rule
                    .entry(rule_name.clone())
                    .or_default()
                    .push((test_desc.clone(), matched_rules.clone()));
            }

            for (rule_name, overlaps) in by_rule.iter() {
                println!("Rule: {}", rule_name);
                for (test_desc, matched_rules) in overlaps {
                    println!("  Test: \"{}\"", test_desc);
                    println!("  Triggered rules: {}", matched_rules.join(", "));
                    println!();
                }
            }

            // Print overlap matrix - which rules appear together most often
            println!("\n========== OVERLAP MATRIX ==========\n");
            let mut rule_pairs: HashMap<(String, String), usize> = HashMap::new();

            for (_, _, matched_rules) in &all_overlaps {
                for i in 0..matched_rules.len() {
                    for j in (i + 1)..matched_rules.len() {
                        let mut pair = [matched_rules[i].clone(), matched_rules[j].clone()];
                        pair.sort();
                        let key = (pair[0].clone(), pair[1].clone());
                        *rule_pairs.entry(key).or_insert(0) += 1;
                    }
                }
            }

            let mut sorted_pairs: Vec<_> = rule_pairs.iter().collect();
            sorted_pairs.sort_by(|a, b| b.1.cmp(a.1));

            println!("Most common rule pairs (top 20):");
            for ((rule1, rule2), count) in sorted_pairs.iter().take(20) {
                println!("  {} <-> {}: {} overlaps", rule1, rule2, count);
            }
        } else {
            println!("No overlaps detected - all rules are unique!");
        }

        println!("\n========== END SMOKE TEST ==========\n");
    }

    /// Test to ensure no rule overlaps exist.
    /// This test will FAIL if any test case triggers multiple rules,
    /// preventing accidental introduction of duplicate detection logic.
    #[test]
    fn test_no_rule_overlaps() {
        let engine = new_engine();
        let mut overlaps_found = Vec::new();

        let fixtures = load_rule_fixtures(std::path::Path::new("rules"))
            .expect("failed to load rule fixtures for overlap test");

        // Process each rule file and test for overlaps
        for rule in &fixtures {
            // Test each positive test case (should_match: true)
            for (i, tc) in rule.tests.iter().enumerate() {
                if !tc.should_match {
                    continue;
                }

                let event = event_from_test_case(tc);
                let matches = engine.eval(&event);

                // Check if multiple rules matched
                if matches.len() > 1 {
                    let matched_rules: Vec<String> =
                        matches.iter().map(|m| m.name.clone()).collect();

                    // Check if all overlapping rules are in the allowed list
                    let other_rules: Vec<String> = matched_rules
                        .iter()
                        .filter(|r| *r != &rule.name)
                        .cloned()
                        .collect();

                    let all_allowed = other_rules
                        .iter()
                        .all(|r| rule.overlap_allowed_with.contains(r));

                    if all_allowed {
                        continue; // All overlaps are explicitly allowed
                    }

                    // Only flag as overlap if rules are in the same category
                    let has_same_category_overlap = {
                        let mut same_category = false;
                        for i in 0..matched_rules.len() {
                            for j in (i + 1)..matched_rules.len() {
                                let cat_i = matched_rules[i].split('_').next().unwrap_or("");
                                let cat_j = matched_rules[j].split('_').next().unwrap_or("");

                                // Both are sigma rules, or both are rta rules, or neither starts with known prefix
                                if (cat_i == "sigma" && cat_j == "sigma")
                                    || (cat_i == "rta" && cat_j == "rta")
                                    || (cat_i != "sigma"
                                        && cat_i != "rta"
                                        && cat_j != "sigma"
                                        && cat_j != "rta")
                                {
                                    same_category = true;
                                    break;
                                }
                            }
                            if same_category {
                                break;
                            }
                        }
                        same_category
                    };

                    if has_same_category_overlap {
                        let disallowed_overlaps: Vec<String> = other_rules
                            .iter()
                            .filter(|r| !rule.overlap_allowed_with.contains(r))
                            .cloned()
                            .collect();

                        overlaps_found.push(format!(
                            "Rule '{}' test #{} ('{}') triggered {} rules in SAME CATEGORY: [{}]\n  \
                             Disallowed overlaps: [{}]\n  \
                             Fix: Add to 'overlap_allowed_with: [{}]' in rule YAML, or improve test cases",
                            rule.name,
                            i,
                            tc.cleartext,
                            matches.len(),
                            matched_rules.join(", "),
                            disallowed_overlaps.join(", "),
                            disallowed_overlaps.join(", ")
                        ));
                    }
                }
            }
        }

        // Assert no overlaps were found
        assert!(
            overlaps_found.is_empty(),
            "\n\nRULE OVERLAP DETECTED!\n\
            Found {} test case(s) that trigger multiple rules:\n\n{}\n\n\
            To fix: Remove duplicate rules or make them mutually exclusive.\n\
            Run `cargo test smoke_test_rule_overlap_detection -- --nocapture` for detailed analysis.\n",
            overlaps_found.len(),
            overlaps_found.join("\n")
        );
    }
}
