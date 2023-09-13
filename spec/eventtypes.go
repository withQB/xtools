package spec

const (
	// Join is the string constant "join"
	Join = "join"
	// Ban is the string constant "ban"
	Ban = "ban"
	// Leave is the string constant "leave"
	Leave = "leave"
	// Invite is the string constant "invite"
	Invite = "invite"
	// Knock is the string constant "knock"
	Knock = "knock"
	// Restricted is the string constant "restricted"
	Restricted = "restricted"
	// NOTSPEC: Restricted is the string constant "knock_restricted" (MSC3787)
	// REVIEW: the MSC is merged though... so is this specced? Idk.
	KnockRestricted = "knock_restricted"
	// NOTSPEC: Peek is the string constant "peek" (MSC2753, used as the label in the sync block)
	Peek = "peek"
	// Public is the string constant "public"
	Public = "public"
	// WorldReadable is the string constant "world_readable"
	WorldReadable = "world_readable"
	// Frame creation preset enum used to create private frames
	PresetPrivateChat = "private_chat"
	// Frame creation preset enum used to create trusted private frames
	PresetTrustedPrivateChat = "trusted_private_chat"
	// Frame creation preset enum used to create public frames
	PresetPublicChat = "public_chat"
	// MFrameCreate 
	MFrameCreate = "m.frame.create"
	// MFrameJoinRules 
	MFrameJoinRules = "m.frame.join_rules"
	// MFramePowerLevels
	MFramePowerLevels = "m.frame.power_levels"
	// MFrameName 
	MFrameName = "m.frame.name"
	// MFrameTopic
	MFrameTopic = "m.frame.topic"
	// MFrameAvatar
	MFrameAvatar = "m.frame.avatar"
	// MFrameMember
	MFrameMember = "m.frame.member"
	// MFrameThirdPartyInvite
	MFrameThirdPartyInvite = "m.frame.third_party_invite"
	// MFrameAliases
	MFrameAliases = "m.frame.aliases"
	// MFrameCanonicalAlias
	MFrameCanonicalAlias = "m.frame.canonical_alias"
	// MFrameHistoryVisibility
	MFrameHistoryVisibility = "m.frame.history_visibility"
	// MFrameGuestAccess
	MFrameGuestAccess = "m.frame.guest_access"
	// MFrameEncryption
	MFrameEncryption = "m.frame.encryption"
	// MFrameRedaction
	MFrameRedaction = "m.frame.redaction"
	// MTyping
	MTyping = "m.typing"
	// MDirectToDevice
	MDirectToDevice = "m.direct_to_device"
	// MDeviceListUpdate
	MDeviceListUpdate = "m.device_list_update"
	// MReceipt
	MReceipt = "m.receipt"
	// MPresence
	MPresence = "m.presence"
	// MFrameMembership
	MFrameMembership = "m.frame_membership"
	// MSpaceChild
	MSpaceChild = "m.space.child"
	// MSpaceParent
	MSpaceParent = "m.space.parent"
)
