#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
#include <freeDiameter/libfdproto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

struct dict_object *session_id = NULL;
struct dict_object *termination_cause = NULL;
struct dict_object *origin_host = NULL;
struct dict_object *origin_realm = NULL;
struct dict_object *destination_host = NULL;
struct dict_object *destination_realm = NULL;
struct dict_object *user_name = NULL;
struct dict_object *origin_state_id = NULL;
struct dict_object *event_timestamp = NULL;
struct dict_object *subscription_id = NULL;
struct dict_object *subscription_id_type = NULL;
struct dict_object *subscription_id_data = NULL;
struct dict_object *auth_session_state = NULL;
struct dict_object *auth_application_id = NULL;
struct dict_object *auth_request_type = NULL;
struct dict_object *re_auth_request_type = NULL;
struct dict_object *result_code = NULL;
struct dict_object *experimental_result = NULL;
struct dict_object *experimental_result_code = NULL;
struct dict_object *vendor_specific_application_id = NULL;
struct dict_object *mip6_agent_info = NULL;
struct dict_object *mip_home_agent_address = NULL;
struct dict_object *authorization_lifetime = NULL;
struct dict_object *auth_grace_period = NULL;
struct dict_object *session_timeout = NULL;
struct dict_object *service_context_id = NULL;
struct dict_object *rat_type = NULL;
struct dict_object *service_selection = NULL;
struct dict_object *visited_plmn_id = NULL;
struct dict_object *visited_network_identifier = NULL;

struct dict_object *vendor = NULL;
struct dict_object *vendor_id = NULL;

struct dict_object *gy_application = NULL;

struct dict_object *gy_cmd_ccr = NULL;
struct dict_object *gy_cmd_cca = NULL;
struct dict_object *gy_cmd_rar = NULL;
struct dict_object *gy_cmd_raa = NULL;

struct dict_object *gy_cc_request_type = NULL;
struct dict_object *gy_cc_request_number = NULL;
struct dict_object *gy_requested_action = NULL;
struct dict_object *gy_aoc_request_type = NULL;
struct dict_object *gy_multiple_services_ind = NULL;
struct dict_object *gy_multiple_services_cc = NULL;
struct dict_object *gy_requested_service_unit = NULL;
struct dict_object *gy_used_service_unit = NULL;
struct dict_object *gy_cc_time = NULL;
struct dict_object *gy_cc_total_octets = NULL;
struct dict_object *gy_cc_input_octets = NULL;
struct dict_object *gy_cc_output_octets = NULL;
struct dict_object *gy_cc_service_specific_units = NULL;
struct dict_object *gy_reporting_reason = NULL;
struct dict_object *gy_service_id = NULL;

struct dict_object *gy_service_information = NULL;
struct dict_object *gy_ps_information = NULL;
struct dict_object *gy_3gpp_charging_id = NULL;
struct dict_object *gy_3gpp_pdp_type = NULL;
struct dict_object *gy_pdp_address = NULL;
struct dict_object *gy_sgsn_address = NULL;
struct dict_object *gy_ggsn_address = NULL;
struct dict_object *gy_3gpp_nsapi = NULL;
struct dict_object *gy_3gpp_selection_mode = NULL;
struct dict_object *gy_3gpp_charging_characteristics = NULL;
struct dict_object *gy_user_equipment_info = NULL;
struct dict_object *gy_user_equipment_info_type = NULL;
struct dict_object *gy_user_equipment_info_value = NULL;

struct dict_object *gy_feature_list_id = NULL;
struct dict_object *gy_feature_list = NULL;
struct dict_object *gy_qos_information = NULL;
struct dict_object *gy_qos_class_identifier = NULL;
struct dict_object *gy_max_requested_bandwidth_ul = NULL;
struct dict_object *gy_max_requested_bandwidth_dl = NULL;
struct dict_object *gy_guaranteed_bitrate_ul = NULL;
struct dict_object *gy_guaranteed_bitrate_dl = NULL;
struct dict_object *gy_allocation_retention_priority = NULL;
struct dict_object *gy_priority_level = NULL;
struct dict_object *gy_pre_emption_capability = NULL;
struct dict_object *gy_pre_emption_vulnerability = NULL;
struct dict_object *gy_apn_aggregate_max_bitrate_ul = NULL;
struct dict_object *gy_apn_aggregate_max_bitrate_dl = NULL;
struct dict_object *gy_3gpp_rat_type = NULL;
struct dict_object *gy_3gpp_user_location_info = NULL;
struct dict_object *gy_called_station_id = NULL;
struct dict_object *gy_3gpp_ms_timezone = NULL;
struct dict_object *gy_charging_rule_base_name = NULL;
struct dict_object *gy_flows = NULL;
struct dict_object *gy_3gpp_sgsn_mcc_mnc = NULL;

static struct session_handler *sess_hdl = NULL;

static int fd_init = 0;
static int sms_credit_ok = 1;
static int cca_pending = 0;

// --- CCA Response Handler ---
int cca_handler(void *cbdata, struct msg **msg)
{
    struct msg *response = *msg;
    struct avp *avp = NULL;
    struct avp_hdr *hdr = NULL;
    struct session *session;
    int new;
    int ret = 0;
    cca_pending = 1;

    printf("Received Credit-Control-Answer (CCA):\n");

    CHECK_FCT(fd_msg_search_avp(*msg, gy_cc_request_number, &avp));
    CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
    printf("Request-Number: %u\n", hdr->avp_value->i32);

    CHECK_FCT(fd_msg_search_avp(*msg, result_code, &avp));
    CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
    printf("Result Code: %d\n", hdr->avp_value->i32);

    if (hdr->avp_value->i32 == 2001) sms_credit_ok = 0; 
    CHECK_FCT(fd_msg_free(*msg));
    *msg = NULL;
    cca_pending = 0;
    return 0;
}

static int gy_fb_cb(struct msg **msg, struct avp *avp,
                        struct session *sess, void *opaque, enum disp_action *act)
{
    return 0;
}

static int gy_rar_cb(struct msg **msg, struct avp *avp,
                         struct session *session, void *opaque, enum disp_action *act)
{
    return 0;
}
struct sess_state
{
    os0_t gy_sid; /* Gy Session-Id */

    os0_t peer_host; /* Peer Host */

#define NUM_CC_REQUEST_SLOT 4

    int32_t sess_id;
    struct
    {
        uint32_t cc_req_no;
        bool pfcp;
        int32_t id; 
    } xact_data[NUM_CC_REQUEST_SLOT];
    uint32_t cc_request_type;
    uint32_t cc_request_number;

    struct timespec ts; /* Time of sending the message */
};

static void state_cleanup(struct sess_state *sess_data, os0_t sid, void *opaque)
{
    if (!sess_data)
    {
        printf("No session state");
        return;
    }
}

int init_dicts()
{

    vendor_id_t vid = 10415; 

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_VENDOR, VENDOR_BY_ID, (void *)&vid, &vendor, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Vendor-Id", &vendor_id, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &session_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Termination-Cause", &termination_cause, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Host", &origin_host, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Realm", &origin_realm, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Host", &destination_host, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Realm", &destination_realm, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "User-Name", &user_name, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-State-Id", &origin_state_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Event-Timestamp", &event_timestamp, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Subscription-Id", &subscription_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Subscription-Id-Type", &subscription_id_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Subscription-Id-Data", &subscription_id_data, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Session-State", &auth_session_state, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", &auth_application_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Request-Type", &auth_request_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Re-Auth-Request-Type", &re_auth_request_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Result-Code", &result_code, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Experimental-Result", &experimental_result, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Experimental-Result-Code", &experimental_result_code, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Vendor-Specific-Application-Id", &vendor_specific_application_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "MIP6-Agent-Info", &mip6_agent_info, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "MIP-Home-Agent-Address", &mip_home_agent_address, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Authorization-Lifetime", &authorization_lifetime, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Grace-Period", &auth_grace_period, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Timeout", &session_timeout, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Service-Context-Id", &service_context_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "RAT-Type", &rat_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Service-Selection", &service_selection, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Visited-PLMN-Id", &visited_plmn_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Visited-Network-Identifier", &visited_network_identifier, ENOENT));

    application_id_t id = 4; // GY APP ID

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_ID, (void *)&id, &gy_application, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Credit-Control-Request", &gy_cmd_ccr, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Credit-Control-Answer", &gy_cmd_cca, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Re-Auth-Request", &gy_cmd_rar, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Re-Auth-Answer", &gy_cmd_raa, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Request-Type", &gy_cc_request_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Request-Number", &gy_cc_request_number, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Requested-Action", &gy_requested_action, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "AoC-Request-Type", &gy_aoc_request_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Multiple-Services-Indicator", &gy_multiple_services_ind, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Multiple-Services-Credit-Control", &gy_multiple_services_cc, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Requested-Service-Unit", &gy_requested_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Used-Service-Unit", &gy_used_service_unit, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Time", &gy_cc_time, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Total-Octets", &gy_cc_total_octets, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Input-Octets", &gy_cc_input_octets, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Output-Octets", &gy_cc_output_octets, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "CC-Service-Specific-Units", &gy_cc_service_specific_units, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Reporting-Reason", &gy_reporting_reason, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Service-Identifier", &gy_service_id, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Service-Information", &gy_service_information, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "PS-Information", &gy_ps_information, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-Charging-Id", &gy_3gpp_charging_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-PDP-Type", &gy_3gpp_pdp_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "PDP-Address", &gy_pdp_address, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "SGSN-Address", &gy_sgsn_address, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "GGSN-Address", &gy_ggsn_address, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-NSAPI", &gy_3gpp_nsapi, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-Selection-Mode", &gy_3gpp_selection_mode, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-Charging-Characteristics", &gy_3gpp_charging_characteristics, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "User-Equipment-Info", &gy_user_equipment_info, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "User-Equipment-Info-Type", &gy_user_equipment_info_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "User-Equipment-Info-Value", &gy_user_equipment_info_value, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Feature-List-ID", &gy_feature_list_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Feature-List", &gy_feature_list, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "QoS-Information", &gy_qos_information, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "QoS-Class-Identifier", &gy_qos_class_identifier, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Max-Requested-Bandwidth-UL", &gy_max_requested_bandwidth_ul, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Max-Requested-Bandwidth-DL", &gy_max_requested_bandwidth_dl, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Guaranteed-Bitrate-UL", &gy_guaranteed_bitrate_ul, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Guaranteed-Bitrate-DL", &gy_guaranteed_bitrate_dl, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Allocation-Retention-Priority", &gy_allocation_retention_priority, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Priority-Level", &gy_priority_level, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Pre-emption-Capability", &gy_pre_emption_capability, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Pre-emption-Vulnerability", &gy_pre_emption_vulnerability, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "APN-Aggregate-Max-Bitrate-UL", &gy_apn_aggregate_max_bitrate_ul, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "APN-Aggregate-Max-Bitrate-DL", &gy_apn_aggregate_max_bitrate_dl, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-RAT-Type", &gy_3gpp_rat_type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-User-Location-Info", &gy_3gpp_user_location_info, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Called-Station-Id", &gy_called_station_id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-MS-TimeZone", &gy_3gpp_ms_timezone, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Charging-Rule-Base-Name", &gy_charging_rule_base_name, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Flows", &gy_flows, ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "3GPP-SGSN-MCC-MNC", &gy_3gpp_sgsn_mcc_mnc, ENOENT));

    return 0;
}

int sms_credit(char* imsi)
{
    struct session *sess = NULL;
    char *sid = NULL;
    struct msg *req = NULL;
    struct dict_object *ccr_model = NULL;
    struct dict_object *avp_model = NULL;
    struct avp *avp = NULL;
    struct disp_when data;
    struct msg_hdr *h;
    struct session *session = NULL;
    struct sess_state *sess_data = NULL, *svg;
    union avp_value val;
    struct avp *avpch1, *avpch2;

    // reset credit check
    sms_credit_ok = 1;
    cca_pending = 0;

    if (fd_init != 0) goto skip_fd_init;
    printf("initialize free diameter\n");

    // Initialize freeDiameter
    CHECK_FCT(fd_core_initialize());
    CHECK_FCT(fd_core_parseconf("freeDiameter.conf"));
    CHECK_FCT(fd_sess_handler_create(&sess_hdl, state_cleanup, NULL, NULL));

    printf("init dicts\n");
    init_dicts();

    printf("register dispatch call backs\n");
    memset(&data, 0, sizeof(data));

    data.app = gy_application;
    static struct disp_hdl *hdl_gy_fb = NULL;
    static struct disp_hdl *hdl_gy_rar = NULL;
    CHECK_FCT(fd_disp_register(gy_fb_cb, DISP_HOW_APPID, &data, NULL, &hdl_gy_fb));

    data.command = gy_cmd_rar;
    CHECK_FCT(fd_disp_register(gy_rar_cb, DISP_HOW_CC, &data, NULL, &hdl_gy_rar));
    CHECK_FCT(fd_disp_app_support(gy_application, NULL, 1, 0));
    CHECK_FCT(fd_core_start());
    CHECK_FCT(fd_core_waitstartcomplete());

    sleep(1);

    fd_init = 1;

    // Build CCR request

skip_fd_init:

    CHECK_FCT(fd_msg_new(gy_cmd_ccr, MSGFL_ALLOC_ETEID, &req));

    CHECK_FCT(fd_msg_hdr(req, &h));
    h->msg_appl = 4;

    CHECK_FCT(fd_msg_new_session(req, NULL, 0));
    CHECK_FCT(fd_msg_sess_get(fd_g_config->cnf_dict, req, &session, NULL));
    CHECK_FCT(fd_sess_state_retrieve(sess_hdl, session, &sess_data));

    CHECK_FCT(fd_msg_add_origin(req, 0));

    val.os.data = (uint8_t *)"epc.mnc001.mcc001.3gppnetwork.org";
    val.os.len = strlen("epc.mnc001.mcc001.3gppnetwork.org");
    CHECK_FCT(fd_msg_avp_new(destination_realm, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    val.i32 = 4;
    CHECK_FCT(fd_msg_avp_new(auth_application_id, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    const char *service_context_id = "32274@3gpp.org";
    val.os.data = (unsigned char *)service_context_id;
    val.os.len = strlen(service_context_id);
    CHECK_FCT(fd_msg_avp_new(service_context_id, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    val.os.data = (uint8_t *)"ocs.epc.mnc001.mcc001.3gppnetwork.org";
    val.os.len = strlen("ocs.epc.mnc001.mcc001.3gppnetwork.org");
    CHECK_FCT(fd_msg_avp_new(destination_host, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    val.i32 = 1; // INITIAL_REQUEST
    CHECK_FCT(fd_msg_avp_new(gy_cc_request_type, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    val.i32 = 0; // First request
    CHECK_FCT(fd_msg_avp_new(gy_cc_request_number, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    val.os.data = (uint8_t *) imsi;
    val.os.len = strlen(imsi);
    CHECK_FCT(fd_msg_avp_new(user_name, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    CHECK_FCT(fd_msg_avp_new(subscription_id, 0, &avp));
    CHECK_FCT(fd_msg_avp_new(subscription_id_type, 0, &avpch1));

    val.i32 = 1; // SUBSCRIPTION_ID_TYPE_END_USER_IMSI;
    CHECK_FCT(fd_msg_avp_setvalue(avpch1, &val));
    CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1));
    CHECK_FCT(fd_msg_avp_new(subscription_id_data, 0, &avpch1));
    
    val.os.data = (uint8_t *) imsi;
    val.os.len = strlen(imsi);
    CHECK_FCT(fd_msg_avp_setvalue(avpch1, &val));
    CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1));

    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));

    val.i32 = 0; // GY_REQUESTED_ACTION_DIRECT_DEBITING
    CHECK_FCT(fd_msg_avp_new(gy_requested_action, 0, &avp));
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));


    CHECK_FCT(fd_msg_avp_new(gy_multiple_services_cc, 0, &avp));
    CHECK_FCT(fd_msg_avp_new(gy_requested_service_unit, 0, &avpch1));
    CHECK_FCT(fd_msg_avp_new(gy_cc_service_specific_units, 0, &avpch2));

    val.u64 = 1; 
    CHECK_FCT(fd_msg_avp_setvalue(avpch2, &val));
    CHECK_FCT(fd_msg_avp_add(avpch1, MSG_BRW_LAST_CHILD, avpch2));
    CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));



    CHECK_FCT(fd_sess_state_store(sess_hdl, session, &sess_data));



    CHECK_FCT(fd_msg_send(&req, cca_handler, svg));

    // Wait for response
    // sleep(5); // let dispatcher receive the CCA

    int time_out = 0;
    while(cca_pending == 1 && time_out < 50) {
        sleep(0.1);
        time_out++;
    }    

    return sms_credit_ok;

    // Cleanup
    // CHECK_FCT(fd_core_shutdown());
    // CHECK_FCT(fd_core_wait_shutdown_complete());
    // return sms_credit_ok;
}
