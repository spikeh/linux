/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifndef _FBNIC_MAC_H_
#define _FBNIC_MAC_H_

#include <linux/ethtool.h>
#include <linux/types.h>

struct fbnic_rmon_hist_range;
struct fbnic_rmon_stats;
struct fbnic_eth_ctrl_stats;
struct fbnic_eth_mac_stats;
struct fbnic_pause_stats;
struct fbnic_fec_stats;
struct fbnic_dev;
struct fbnic_net;

#define FBNIC_MAX_JUMBO_FRAME_SIZE	9742

enum {
	FBNIC_LINK_DISABLED	= 0,
	FBNIC_LINK_DOWN		= 1,
	FBNIC_LINK_UP		= 2,
	FBNIC_LINK_EVENT	= 3,
};

enum {
	FBNIC_LED_STROBE_INIT,
	FBNIC_LED_ON,
	FBNIC_LED_OFF,
	FBNIC_LED_RESTORE,
};

/* Treat the FEC bits as a bitmask laid out as follows:
 * Bit 0: RS Enabled
 * Bit 1: BASER(Firecode) Enabled
 * Bit 2: Autoneg FEC
 */
enum {
	FBNIC_FEC_OFF		= 0,
	FBNIC_FEC_RS		= 1,
	FBNIC_FEC_BASER		= 2,
	FBNIC_FEC_AUTO		= 4,
};

#define FBNIC_FEC_MODE_MASK	(FBNIC_FEC_AUTO - 1)

/* Treat the link modes as a set of moldulation/lanes bitmask:
 * Bit 0: Lane Count, 0 = R1, 1 = R2
 * Bit 1: Modulation, 0 = NRZ, 1 = PAM4
 * Bit 2: Autoneg Modulation/Lane Configuration
 */
enum {
	FBNIC_LINK_25R1		= 0,
	FBNIC_LINK_50R2		= 1,
	FBNIC_LINK_50R1		= 2,
	FBNIC_LINK_100R2	= 3,
	FBNIC_LINK_AUTO		= 4,
};

#define FBNIC_LINK_MODE_R2	(FBNIC_LINK_50R2)
#define FBNIC_LINK_MODE_PAM4	(FBNIC_LINK_50R1)
#define FBNIC_LINK_MODE_MASK	(FBNIC_LINK_AUTO - 1)

enum fbnic_sensor_id {
	FBNIC_SENSOR_TEMP,		/* Temp in millidegrees Centigrade */
	FBNIC_SENSOR_VOLTAGE,		/* Voltage in millivolts */
};

/* This structure defines the interface hooks for the CMAC. The CMAC hooks
 * will be configured as a const struct provided with a set of function
 * pointers.
 *
 * TBD: The reason for doing this as a struct of function pointers is that
 * we may have to support up to 3 different CMAC types; QEMU, FPGA, and
 * ASIC.
 *
 * int (*set_addr)(struct fbnic_dev *fbd);
 *	Overwrite the DSN based on information provided by the firmware
 * bool (*get_link)(struct fbnic_dev *fbd);
 *	Get the current link state for the MAC.
 * int (*get_link_event)(struct fbnic_dev *fbd)
 *	Get the current link event status, reports true if link has
 *	changed to either up (1) or down (-1).
 * void (*enable)(struct fbnic_dev *fbd);
 *	Configure and enable CMAC to enable link if not already enabled
 * void (*disable)(struct fbnic_dev *fbd);
 *	Shutdown the link if we are the only consumer of it.
 * void (*init_regs)(struct fbnic_dev *fbd);
 *	Initialize MAC registers to enable Tx/Rx paths and FIFOs.
 * int (*config_fec)(struct fbnic_dev *fbd);
 *	Configure forward error correction.
 * void (*config_pause)(struct fbnic_dev *fbd);
 *	Configure pause settings of the CMAC. Information on what the
 *	configuration should be is pulled from the fbn pointer associated
 *	with the fbd struct.
 *
 * void (*get_pause_stats)(struct fbnic_dev *fbd, bool reset,
 *			   struct fbnic_pause_stats *pause_stats);
 *	Collect ethtool stats related to flow control from the CMAC
 * void (*get_fec_stats)(struct fbnic_dev *fbd, bool reset,
 *			 struct fbnic_fec_stats *fec_stats);
 *	Collect IEEE 802.3 stats related to forward error correction
 * void (*get_eth_mac_stats)(struct fbnic_dev *fbd, bool reset,
 *			 struct fbnic_eth_mac_stats *mac_stats);
 *	Collect IEEE 802.3 MAC statistics
 * void (*get_rmon_stats)(struct fbnic_dev *fbd, bool reset,
 *			  struct fbnic_rmon_stats *rmon_stats);
 *	Collect RMON (RFC 2819) Statistics
 *
 * void (*get_link_settings)(struct fbnic_dev *fbd,
 *			     struct ethtool_link_ksettings *cmd);
 *	Collect link specific settings
 * int (*set_link_settings)(struct fbnic_dev *fbd,
 *			    const struct ethtool_link_ksettings *cmd);
 *	Configure link specific settings
 *
 * int (*get_sensor)(struct fbnic_dev *fbd, int id, long *val)
 *	Places sensor data based on id in val.
 * int (*enable_loopback)(struct fbnic_dev *fbd)
 *	Places the MAC in a loopback state to enable loopback testing
 *
 * void (*set_led_state)(struct fbnic_dev *fbd, int state)
 *	Used to control the LED state of the port/slice
 *
 * rmon_ranges
 *	Pointer to the RMON ranges supported by the device
 * eeprom_len
 *	Length of FRU EEPROM in bytes
 */
struct fbnic_mac {
	int (*set_addr)(struct fbnic_dev *fbd);
	bool (*get_link)(struct fbnic_dev *fbd);
	int (*get_link_event)(struct fbnic_dev *fbd);
	int (*enable)(struct fbnic_dev *fbd);
	void (*disable)(struct fbnic_dev *fbd);
	void (*init_regs)(struct fbnic_dev *fbd);
	int (*config_fec)(struct fbnic_dev *fbd);
	void (*config_pause)(struct fbnic_dev *fbd);

	void (*get_pause_stats)(struct fbnic_dev *fbd, bool reset,
				struct fbnic_pause_stats *pause_stats);
	void (*get_fec_stats)(struct fbnic_dev *fbd, bool reset,
			      struct fbnic_fec_stats *fec_stats);
	void (*get_eth_mac_stats)(struct fbnic_dev *fbd, bool reset,
				  struct fbnic_eth_mac_stats *mac_stats);
	void (*get_eth_ctrl_stats)(struct fbnic_dev *fbd, bool reset,
				   struct fbnic_eth_ctrl_stats *ctrl_stats);
	void (*get_rmon_stats)(struct fbnic_dev *fbd, bool reset,
			       struct fbnic_rmon_stats *rmon_stats);

	void (*get_link_settings)(struct fbnic_dev *fbd,
				  struct ethtool_link_ksettings *cmd);
	int (*set_link_settings)(struct fbnic_dev *fbd,
				 const struct ethtool_link_ksettings *cmd);

	int (*get_sensor)(struct fbnic_dev *fbd, int id, long *val);
	int (*enable_loopback)(struct fbnic_dev *fbd);

	void (*set_led_state)(struct fbnic_dev *fbd, int state);

	const struct fbnic_rmon_hist_range *rmon_ranges;
	unsigned int eeprom_len;
};

bool fbnic_is_asic(struct fbnic_dev *fbd);
int fbnic_mac_init(struct fbnic_dev *fbd);
#endif /* _FBNIC_MAC_H_ */
