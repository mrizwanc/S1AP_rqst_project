/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "asn/s1ap_v12.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER -D include/`
 */

#include "E-RABToBeSwitchedULItem.h"

#include "ProtocolExtensionContainer.h"
asn_TYPE_member_t asn_MBR_E_RABToBeSwitchedULItem_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_RABToBeSwitchedULItem, e_RAB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RAB_ID,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"e-RAB-ID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_RABToBeSwitchedULItem, transportLayerAddress),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportLayerAddress,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"transportLayerAddress"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_RABToBeSwitchedULItem, gTP_TEID),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GTP_TEID,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"gTP-TEID"
		},
	{ ATF_POINTER, 1, offsetof(struct E_RABToBeSwitchedULItem, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolExtensionContainer_5589P5,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_E_RABToBeSwitchedULItem_oms_1[] = { 3 };
static const ber_tlv_tag_t asn_DEF_E_RABToBeSwitchedULItem_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_E_RABToBeSwitchedULItem_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-RAB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* transportLayerAddress */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* gTP-TEID */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_E_RABToBeSwitchedULItem_specs_1 = {
	sizeof(struct E_RABToBeSwitchedULItem),
	offsetof(struct E_RABToBeSwitchedULItem, _asn_ctx),
	asn_MAP_E_RABToBeSwitchedULItem_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_E_RABToBeSwitchedULItem_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_E_RABToBeSwitchedULItem = {
	"E-RABToBeSwitchedULItem",
	"E-RABToBeSwitchedULItem",
	&asn_OP_SEQUENCE,
	asn_DEF_E_RABToBeSwitchedULItem_tags_1,
	sizeof(asn_DEF_E_RABToBeSwitchedULItem_tags_1)
		/sizeof(asn_DEF_E_RABToBeSwitchedULItem_tags_1[0]), /* 1 */
	asn_DEF_E_RABToBeSwitchedULItem_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_RABToBeSwitchedULItem_tags_1)
		/sizeof(asn_DEF_E_RABToBeSwitchedULItem_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_E_RABToBeSwitchedULItem_1,
	4,	/* Elements count */
	&asn_SPC_E_RABToBeSwitchedULItem_specs_1	/* Additional specs */
};

