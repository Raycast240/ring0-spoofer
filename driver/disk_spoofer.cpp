// ============================================================================
// disk_spoofer.cpp -- disk / volume / platform identifier spoof.
//
// Patch set (registry caches 1-5, plus a live storage-stack interception 6;
// a storport device-extension patch would need per-build PDB offsets a
// mapped driver cannot resolve, so the live path is covered at the
// \Driver\Disk dispatch boundary instead -- the same surface the reference
// tree hooks, hardened for the synchronous-complete reality of disk.sys):
//   1. HARDWARE\DEVICEMAP\Scsi Port#Bus#TargetId#Lun\SerialNumber -- the
//      devicemap serial copy many identification routines read;
//      slight-change transform in place, stale DeviceIdentifierPage removed
//   2. SYSTEM\MountedDevices -- every \DosDevices\Volume{...} /
//      \??\Volume{...} value renamed to a fresh random GUID (data preserved)
//   3. SYSTEM\HardwareConfig -- LastConfig GUID replaced (+ its subkey
//      renamed, values carried over)
//   4. SOFTWARE\Microsoft\Cryptography\MachineGuid -- fresh random GUID
//   5. SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId -- slight-
//      change digit drift (a small subset of the digits changes, length/
//      dashes kept, activation blobs DigitalProductId[4] untouched)
//   6. \Driver\Disk IRP_MJ_DEVICE_CONTROL dispatch interception -- the
//      serial in every completed IOCTL_STORAGE_QUERY_PROPERTY response
//      (the live query WMI Win32_DiskDrive and every hwid library uses) is
//      rewritten with the SAME idempotent slight-change transform + salt as
//      1, so the cached devicemap copy and the live answer agree (and an
//      already-patched answer never drifts). SHIPPED since 2026-09-06.
// every mutating surface is one-shot per install; a repeated op-17 is a
// no-op, not a re-mutation.
// ============================================================================

#include <impl/includes.h>

namespace spoof::disk {

	namespace {

		// salt for every disk serial transform: the devicemap registry copy
		// (patch 1) and the live \Driver\Disk ioctl answers (patch 6) must
		// derive the same spoofed bytes from the same original bytes
		constexpr std::uint32_t k_serial_salt = 0x0D15u;

		// ---- 1. SCSI devicemap serials ------------------------------------

		bool patch_scsi_devicemap( ) {
			HANDLE root = nullptr;
			if ( !kreg::open_key( &root,
					L"\\REGISTRY\\MACHINE\\HARDWARE\\DEVICEMAP\\Scsi",
					KEY_READ | KEY_ENUMERATE_SUB_KEYS ) ) {
				return false;
			}

			std::uint32_t patched = 0;
			// devicemap paths are ~70 chars worst case; 160 wchars is ample
			// and keeps this recursive-looking walk's four nested buffers well
			// under a 4KB stack frame (no __chkstk, smaller mapped image)
			constexpr std::size_t k_path_cch = 160;
			for ( ULONG pi = 0;; ++pi ) {
				wchar_t port[ kreg::k_max_name ]{ };
				if ( !kreg::enum_subkey( root, pi, port, kreg::k_max_name ) )
					break;

				wchar_t port_path[ k_path_cch ]{ };
				if ( !kreg::join_path( port_path, k_path_cch, L"\\REGISTRY\\MACHINE\\HARDWARE\\DEVICEMAP\\Scsi", port ) )
					continue;
				HANDLE bus_root = nullptr;
				if ( !kreg::open_key( &bus_root, port_path, KEY_READ | KEY_ENUMERATE_SUB_KEYS ) )
					continue;

				for ( ULONG bi = 0;; ++bi ) {
					wchar_t bus[ kreg::k_max_name ]{ };
					if ( !kreg::enum_subkey( bus_root, bi, bus, kreg::k_max_name ) )
						break;

					wchar_t bus_path[ k_path_cch ]{ };
					if ( !kreg::join_path( bus_path, k_path_cch, port_path, bus ) )
						continue;
					HANDLE target_root = nullptr;
					if ( !kreg::open_key( &target_root, bus_path, KEY_READ | KEY_ENUMERATE_SUB_KEYS ) ) {
						continue;
					}

					for ( ULONG ti = 0;; ++ti ) {
						wchar_t target[ kreg::k_max_name ]{ };
						if ( !kreg::enum_subkey( target_root, ti, target, kreg::k_max_name ) )
							break;

					wchar_t target_path[ k_path_cch ]{ };
						if ( !kreg::join_path( target_path, k_path_cch, bus_path, target ) )
							continue;
						HANDLE lun_root = nullptr;
						if ( !kreg::open_key( &lun_root, target_path, KEY_READ | KEY_ENUMERATE_SUB_KEYS ) )
							continue;

						for ( ULONG li = 0;; ++li ) {
							wchar_t lun[ kreg::k_max_name ]{ };
							if ( !kreg::enum_subkey( lun_root, li, lun, kreg::k_max_name ) )
								break;

						wchar_t lun_path[ k_path_cch ]{ };
							if ( !kreg::join_path( lun_path, k_path_cch, target_path, lun ) )
								continue;
							HANDLE lun_key = nullptr;
							if ( !kreg::open_key( &lun_key, lun_path,
									KEY_QUERY_VALUE | KEY_SET_VALUE ) )
								continue;

							// deterministic-within-boot, IDEMPOTENT slight-change
							// transform of the whole serial (shape preserved:
							// digits stay digits, letters stay letters, length
							// never changes, only ~30% of alnum positions
							// drift). the SAME transform + salt runs in the
							// \Driver\Disk dispatch hook (patch 6), so this
							// cached copy and the live ioctl answer agree --
							// even when the registry copy was already patched
							// by an earlier install (both hold the same bytes,
							// both land on the same spoofed output, changed=
							// false). EVERY lun is patched: the transform is
							// idempotent, so a repeated op-17 (latched off at
							// the stage level anyway) and a multi-disk box
							// both stay consistent -- the old first-lun-only
							// latch left drive 2+ desynced from their live
							// ioctl answers.
							ULONG type = 0;
							ULONG len = 0;
							wchar_t serial[ 128 ]{ };
							UCHAR raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 256 ]{ };
							if ( kreg::query_value( lun_key, L"SerialNumber", &type, raw,
									sizeof( raw ) - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len )
								&& type == REG_SZ
								&& len >= sizeof( wchar_t ) && len <= sizeof( serial ) ) {
								const auto chars = len / sizeof( wchar_t );
								memcpy( serial, raw, len );
								// strip the terminating NUL(s) so the seed matches the
								// hook's hash of the bare serial bytes (the wide variant
								// hashes the narrow projection of exactly what the ascii
								// variant hashes)
								auto slen = chars;
								while ( slen && !serial[ slen - 1 ] )
									--slen;
								// same length window as the hook (4..60): a serial outside
								// it is left untouched in BOTH places, so the registry copy
								// and the live answer can never desynchronize over a length
								// edge case
								if ( slen >= 4 && slen <= 60
									&& spoof::randomize_chars_w( serial, slen, k_serial_salt )
								&& kreg::set_value( lun_key, L"SerialNumber", REG_SZ,
									serial, len ) ) {
									++patched;
								}
							}

							// stale VPD page cache: drop, it is rebuilt on use
							kreg::delete_value( lun_key, L"DeviceIdentifierPage" );

							kreg::close_key( lun_key );
						}
						kreg::close_key( lun_root );
					}
					kreg::close_key( target_root );
				}
				kreg::close_key( bus_root );
			}
			kreg::close_key( root );
			return patched != 0;
		}

		// ---- 2. MountedDevices volume GUID renames -------------------------

		bool patch_mounted_devices( ) {
			HANDLE key = nullptr;
			if ( !kreg::open_key( &key, L"\\REGISTRY\\MACHINE\\SYSTEM\\MountedDevices",
					KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS ) ) {
				return false;
			}

			std::uint32_t patched = 0;
			// deleting a value shifts every following value down one index, so
			// a successful rename/delete must RE-ENUMERATE the same index;
			// only non-matching (untouched) values advance the index. the old
			// loop always advanced and silently skipped every second volume.
			for ( ULONG idx = 0;; ) {
				wchar_t name[ kreg::k_max_name ]{ };
				ULONG type = 0;
				std::uint8_t* data = nullptr;
				ULONG data_len = 0;
				const bool have = kreg::enum_value_alloc( key, idx, name, kreg::k_max_name,
					&type, &data, &data_len );

				if ( have ) {
					const bool dos_volume = kreg::wstarts( name, L"\\DosDevices\\Volume{" );
					const bool qm_volume = kreg::wstarts( name, L"\\??\\Volume{" );
					if ( !dos_volume && !qm_volume ) {
						kernel::ex_free_pool_with_tag( data, 'vReS' );
						++idx;
						continue;
					}

					// new name: same prefix shape + a fresh GUID
					const wchar_t* prefix = dos_volume ? L"\\DosDevices\\Volume" : L"\\??\\Volume";
					wchar_t new_name[ 80 ]{ };
					auto* w = new_name;
					for ( auto* p = const_cast< wchar_t* >( prefix ); *p; )
						*w++ = *p++;
					wchar_t guid[ 40 ]{ };
					spoof::format_guid( guid, 40, spoof::make_guid( ) );
					for ( auto* p = guid; *p; )
						*w++ = *p++;

					if ( kreg::set_value( key, new_name, type, data, data_len )
						&& kreg::delete_value( key, name ) ) {
						++patched;
						// re-enumerate this index: the next value moved here
					} else {
						++idx;
					}
					kernel::ex_free_pool_with_tag( data, 'vReS' );
					continue;
				}

				// enumeration ended or the record was rejected (oversized /
				// unprintable name): advancing never loops forever because the
				// rejected case still consumes one real value slot
				if ( !have ) {
					// distinguish hard end from a rejected record: probe the
					// next index with a name-only enumeration
					wchar_t probe_name[ kreg::k_max_name ]{ };
					if ( !kreg::enum_value( key, idx, probe_name, kreg::k_max_name ) )
						break;
					++idx;
				}
			}

			kreg::close_key( key );
			return patched != 0;
		}

		// ---- 3. HardwareConfig LastConfig GUID ----------------------------

		bool patch_hardware_config( ) {
			HANDLE key = nullptr;
			if ( !kreg::open_key( &key, L"\\REGISTRY\\MACHINE\\SYSTEM\\HardwareConfig",
					KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS ) ) {
				return false;
			}

			// read the old LastConfig GUID so its subkey can be renamed too
			wchar_t old_guid[ 48 ]{ };
			ULONG type = 0;
			ULONG len = 0;
			UCHAR raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 96 ]{ };
			const bool has_old = kreg::query_value( key, L"LastConfig", &type, raw,
				sizeof( raw ) - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len )
				&& type == REG_SZ && len >= sizeof( wchar_t ) && len <= sizeof( old_guid );
			if ( has_old )
				memcpy( old_guid, raw, len );

			wchar_t new_guid[ 40 ]{ };
			spoof::format_guid( new_guid, 40, spoof::make_guid( ) );
			const auto bytes = static_cast< ULONG >( ( kreg::wlen( new_guid ) + 1 ) * sizeof( wchar_t ) );
			const bool value_ok = kreg::set_value( key, L"LastConfig", REG_SZ, new_guid, bytes );

			bool key_ok = false;
			if ( has_old && old_guid[ 0 ] == L'{' ) {
				// open the subkey RELATIVE to the HardwareConfig parent: the
				// old code passed the bare "{...}" name to the full-path open,
				// which always failed and silently disabled the whole carry
				HANDLE old_key = nullptr;
				if ( kreg::open_key_under( &old_key, key, old_guid,
						KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS ) ) {
					// carry every value over to a subkey named by the new GUID
					HANDLE new_key = nullptr;
					if ( kreg::create_subkey( &new_key, key, new_guid ) ) {
						key_ok = true;
						for ( ULONG idx = 0;; ++idx ) {
							wchar_t vname[ kreg::k_max_name ]{ };
							ULONG vtype = 0;
							std::uint8_t* vdata = nullptr;
							ULONG vlen = 0;
							if ( !kreg::enum_value_alloc( old_key, idx, vname, kreg::k_max_name,
									&vtype, &vdata, &vlen ) ) {
								break;
							}
							if ( !kreg::set_value( new_key, vname, vtype, vdata, vlen ) )
								key_ok = false;
							kernel::ex_free_pool_with_tag( vdata, 'vReS' );
						}
						kreg::close_key( new_key );
					}
					if ( key_ok )
						kreg::delete_key( old_key );
					kreg::close_key( old_key );
				}
			}

			kreg::close_key( key );
			return value_ok || key_ok;
		}

		// ---- 4. MachineGuid ------------------------------------------------

		bool patch_machine_guid( ) {
			HANDLE key = nullptr;
			if ( !kreg::open_key( &key,
					L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
					KEY_QUERY_VALUE | KEY_SET_VALUE ) ) {
				return false;
			}

			wchar_t guid[ 40 ]{ };
			spoof::format_guid( guid, 40, spoof::make_guid( ) );
			const auto bytes = static_cast< ULONG >( ( kreg::wlen( guid ) + 1 ) * sizeof( wchar_t ) );
			const auto ok = kreg::set_value( key, L"MachineGuid", REG_SZ, guid, bytes );
			kreg::close_key( key );
			return ok;
		}

		// ---- 5. ProductId ---------------------------------------------------
		//
		// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId -- the
		// retail product id (digit groups separated by dashes). slight-change
		// drift: same length, same dash positions, digits stay digits, and
		// only a small subset of the digits changes (~1 in 4, minimum 2) --
		// "same install family, different license", not a full scramble.
		// DigitalProductId / DigitalProductId4 (the activation blobs) are
		// deliberately untouched -- rewriting those can trip re-activation,
		// and most identification kits only sample the plain REG_SZ.

		bool patch_product_id( ) {
			HANDLE key = nullptr;
			if ( !kreg::open_key( &key,
					L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
					KEY_QUERY_VALUE | KEY_SET_VALUE ) ) {
				return false;
			}

			ULONG type = 0;
			ULONG len = 0;
			UCHAR raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 128 ]{ };
			if ( !kreg::query_value( key, L"ProductId", &type, raw,
					sizeof( raw ) - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len )
				|| type != REG_SZ || len < sizeof( wchar_t ) || len > 100 ) {
				kreg::close_key( key );
				return false;
			}

			// widen into a local, drift a subset of the digits only
			const auto chars = len / sizeof( wchar_t );
			if ( chars == 0 || chars > 50 ) {
				kreg::close_key( key );
				return false;
			}
			wchar_t pid[ 52 ]{ };
			memcpy( pid, raw, len );

			std::uint32_t mutated = 0;
			for ( std::size_t i = 0; i < chars && pid[ i ]; ++i ) {
				if ( pid[ i ] >= L'0' && pid[ i ] <= L'9'
					&& ( spoof::rand_next( ) & 3u ) == 0u ) {
					pid[ i ] = static_cast< wchar_t >( L'0' + ( spoof::rand_next( ) % 10u ) );
					++mutated;
				}
			}
			// minimum-2 guarantee: first digit positions mutate if the subset
			// draw came up short
			for ( std::size_t i = 0; i < chars && mutated < 2; ++i ) {
				if ( pid[ i ] >= L'0' && pid[ i ] <= L'9' ) {
					pid[ i ] = static_cast< wchar_t >( L'0' + ( spoof::rand_next( ) % 10u ) );
					++mutated;
				}
			}
			if ( !mutated ) {
				kreg::close_key( key );
				return false;
			}

			const auto ok = kreg::set_value( key, L"ProductId", REG_SZ, pid, len );
			kreg::close_key( key );
			return ok;
		}

		// ---- 6. deep disk serial: \Driver\Disk dispatch interception ----
		//
		// the registry patches above only cover cached copies. identification
		// kits and anti-cheats read the drive serial LIVE through the storage
		// stack: IOCTL_STORAGE_QUERY_PROPERTY, which is what WMI
		// Win32_DiskDrive and every hwid library use. disk.sys serves that
		// request from its device-extension cache and completes the IRP
		// synchronously INSIDE its dispatch routine, but a lower driver can
		// also complete or pend it -- so the patch runs in BOTH places:
		//   - a completion routine written MANUALLY into our CURRENT stack
		//     location before the original dispatch (NOT IoSetCompletionRoutine,
		//     which stores into the NEXT-LOWER location -- wdm.h -- where a
		//     synchronous disk.sys completion never walks; the walk starts at
		//     the completer's own location and moves UP, so the current
		//     location is the one place the routine is guaranteed to be
		//     invoked from: synchronous self-completion, synchronous
		//     completion from below, and pended IRPs alike), and
		//   - post-dispatch, kept from the shipped design, guarded by the
		//     completion walk having CLEARED our CompletionRoutine (it only
		//     patches when the walk was interrupted below us).
		// the transform is idempotent, and the once-guard keeps the two paths
		// from double-patching anyway. the buffer copy back to usermode
		// happens after every completion routine has run.
		//
		// everything below resolves at RUNTIME through kernel::get_export --
		// the import table of the mapped image stays exactly as it was.

		// the dispatch entry \Driver\Disk shipped with; also the one-shot
		// latch for the hook itself (a repeated op-17 must never re-hook)
		PDRIVER_DISPATCH g_disk_ioctl_original = nullptr;

		// IOCTL_STORAGE_QUERY_PROPERTY:
		// CTL_CODE(IOCTL_STORAGE_BASE=0x2D, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
		constexpr ULONG k_ioctl_storage_query_property = 0x002D1400u;

		// StorageDeviceProperty -- the one query that answers with a
		// STORAGE_DEVICE_DESCRIPTOR (the property id rides the input
		// STORAGE_PROPERTY_QUERY, PropertyId u32 @0; PropertyStandardQuery
		// is also 0)
		constexpr std::uint32_t k_property_storage_device = 0;

		// STORAGE_DEVICE_DESCRIPTOR (ntddstor.h layout, ABI-stable). NOTE:
		// the offsets were re-verified against the WDK header 2026-09-06 --
		// the first shipped copy of this struct spread DeviceType /
		// DeviceTypeModifier over two ULONGs, which shifted every string
		// offset +8: the code read SerialNumberOffset from +0x20 (really
		// RawPropertiesLength, always 0 on this box -> "no serial" -> never
		// patched). the live descriptor on the dev box: Version=40 @0,
		// SerialNumberOffset=139 @0x18, serial 40 bytes ending in '.'
		struct storage_descriptor_t {
			std::uint32_t m_version;                     // +0x00
			std::uint32_t m_size;                       // +0x04
			std::uint8_t  m_device_type;                // +0x08
			std::uint8_t  m_device_type_modifier;      // +0x09
			std::uint8_t  m_removable_media;            // +0x0A
			std::uint8_t  m_command_queueing;           // +0x0B
			std::uint32_t m_vendor_id_offset;           // +0x0C
			std::uint32_t m_product_id_offset;          // +0x10
			std::uint32_t m_product_revision_offset;    // +0x14
			std::uint32_t m_serial_number_offset;       // +0x18
			std::uint32_t m_bus_type;                   // +0x1C
			std::uint32_t m_raw_properties_length;      // +0x20
			std::uint8_t  m_raw_device_properties[ 1 ];// +0x24
		};
		static_assert( offsetof( storage_descriptor_t, m_serial_number_offset ) == 0x18,
			"STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset must be at +0x18" );
		static_assert( offsetof( storage_descriptor_t, m_vendor_id_offset ) == 0x0C,
			"STORAGE_DEVICE_DESCRIPTOR.VendorIdOffset must be at +0x0C" );

		// patch the serial inside a COMPLETED descriptor response (SystemBuffer
		// holds the output STORAGE_DEVICE_DESCRIPTOR at this point -- the
		// buffered input query has been overwritten). callers gate on the
		// PRE-DISPATCH-captured PropertyId; this function never re-reads the
		// buffer's first u32: that is the descriptor's Version (= 40 on every
		// modern build) and the 2026-09-06 gate that read it as the query's
		// PropertyId never passed, which is why the hook shipped dead.
		bool patch_descriptor_serial( PIRP irp ) {
			auto* buffer = static_cast< std::uint8_t* >( irp->AssociatedIrp.SystemBuffer );
			const auto information = static_cast< std::uint32_t >( irp->IoStatus.Information );
			if ( !buffer || information < sizeof( storage_descriptor_t ) + 2 )
				return false;

			auto* desc = reinterpret_cast< storage_descriptor_t* >( buffer );
			const auto serial_off = desc->m_serial_number_offset;
			if ( !serial_off || serial_off >= information - 2 )
				return false;

			// the serial must be a printable, NUL-terminated, sane-length
			// string fully inside the reported data -- anything else is a
			// shape we do not recognize and refuse to touch. the length
			// window 4..60 matches the devicemap registry stage exactly (both
			// sides skip the same serials, so the cached copy and the live
			// answer can never desynchronize over a length edge case); the
			// transform preserves length, so the trailing "." (0x2E) shape
			// NVMe serials carry survives byte-for-byte and the patched
			// serial byte-matches the registry output ("Q827_..._0D96." on
			// the dev box -- same salt 0x0D15, same boot nonce, same input
			// bytes)
			auto* serial = reinterpret_cast< char* >( buffer + serial_off );
			std::uint32_t len = 0;
			while ( len < 64
				&& ( serial_off + len ) < information
				&& serial[ len ] ) {
				const auto c = static_cast< unsigned char >( serial[ len ] );
				if ( c < 0x20 || c > 0x7E )
					return false;
				++len;
			}
			if ( len < 4 || len > 60 || ( serial_off + len ) >= information )
				return false;

			// same deterministic transform + salt as the devicemap copy:
			// repeated reads of the same drive inside one boot agree, and
			// agree with the registry cache when both held the same bytes
			return spoof::randomize_chars( serial, len, k_serial_salt );
		}

		// completion path: written into the hook's CURRENT stack location for
		// StorageDeviceProperty queries BEFORE the original dispatch runs
		// (see disk_ioctl_hook for why IoSetCompletionRoutine is the wrong
		// primitive here -- it targets the next-LOWER location). the io
		// manager's completion walk (IofCompleteRequest) processes every
		// stack location at or above the completer's, so this fires when
		// disk.sys completes the IRP itself (synchronous cache-hit: the walk
		// starts AT our location), when a lower driver completes
		// synchronously inside disk.sys's dispatch, AND when a pended IRP
		// completes later. the system buffer is still alive here: for
		// buffered io it is freed in the requestor's completion APC, after
		// every completion routine ran. the walk CLEARS the location's
		// CompletionRoutine once this has run (IopClearStackLocation), which
		// is the once-guard the post-dispatch path in disk_ioctl_hook relies
		// on.
		NTSTATUS disk_query_completion( PDEVICE_OBJECT, PIRP irp, PVOID ) {
			__try {
				if ( NT_SUCCESS( irp->IoStatus.Status ) )
					( void )patch_descriptor_serial( irp );
			}
			__except ( EXCEPTION_EXECUTE_HANDLER ) {
				// never fail disk io because of the spoof: the irp is
				// already complete either way
			}
			// pass-through observer: keep the pending contract intact for
			// the locations above us (a completion routine returning
			// STATUS_CONTINUE must re-mark a pended IRP before returning)
			if ( irp->PendingReturned )
				IoMarkIrpPending( irp );
			return STATUS_CONTINUE_COMPLETION;
		}

		NTSTATUS disk_ioctl_hook( PDEVICE_OBJECT device_object, PIRP irp ) {
			auto* stack = IoGetCurrentIrpStackLocation( irp );
			const bool is_query = stack
				&& stack->MajorFunction == IRP_MJ_DEVICE_CONTROL
				&& stack->Parameters.DeviceIoControl.IoControlCode
					== k_ioctl_storage_query_property;

			// capture the input PropertyId BEFORE dispatch: the buffered
			// input (STORAGE_PROPERTY_QUERY, PropertyId u32 @0) and the
			// output descriptor share ONE system buffer, and the dispatch
			// overwrites it -- post-dispatch buffer[0] is the descriptor
			// Version, not the PropertyId (the shipped bug: Version=40 != 0
			// -> the gate never passed -> zero serials patched)
			std::uint32_t property_id = 0xFFFFFFFFu;
			bool have_input = false;
			if ( is_query
				&& stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof( ULONG ) ) {
				__try {
					auto* input = static_cast< std::uint8_t* >(
						irp->AssociatedIrp.SystemBuffer );
					if ( input ) {
						std::uint32_t q = 0;
						memcpy( &q, input, sizeof( q ) );
						property_id = q;
						have_input = true;
					}
				}
				__except ( EXCEPTION_EXECUTE_HANDLER ) {
				}
			}

			// only StorageDeviceProperty answers a descriptor; other property
			// ids get no completion routine and no patch.
			//
			// INSTALLED INTO OUR OWN CURRENT STACK LOCATION, MANUALLY -- and
			// deliberately NOT via IoSetCompletionRoutine. this hook IS
			// \Driver\Disk's dispatch entry: when it runs, the current stack
			// location is the slot the SENDER above us (partmgr on the filter
			// stack / the io manager for direct PhysicalDriveN opens) set up.
			// disk.sys serves this ioctl synchronously from its
			// device-extension cache, so when it completes the IRP the io
			// manager's completion walk (IopfCompleteRequest) starts AT our
			// current location and walks upward -- a routine stored there
			// fires; IoSetCompletionRoutine instead writes
			// IoGetNextIrpStackLocation (wdm.h: "invoked once the next level
			// driver completes the packet"), i.e. the location ONE BELOW us
			// that belongs to the driver UNDER disk.sys. that is where the
			// shipped hook parked disk_query_completion: nothing ever walks
			// into it (disk.sys never passes this ioctl down, and a walk
			// starts at the completer's own location and moves UP), so the
			// patch never ran and the live serial stayed real -- the
			// 2026-09-06 hwcheck evidence (hook=ok, serial unchanged hours
			// later with the hook still installed).
			//
			// the free-slot gate keeps us from clobbering a completion
			// routine the sender above installed for itself: if the slot is
			// taken, that IRP is simply not intercepted.
			if ( have_input && property_id == k_property_storage_device
				&& !stack->CompletionRoutine ) {
				stack->CompletionRoutine = disk_query_completion;
				stack->Context = nullptr;
				stack->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR
					| SL_INVOKE_ON_CANCEL;
			}

			const auto status = g_disk_ioctl_original( device_object, irp );

			// post-dispatch belt-and-braces (kept from the shipped design:
			// disk.sys serves this ioctl synchronously from its
			// device-extension cache). the completion walk has normally
			// ALREADY patched + cleared our location inside the call above;
			// the CompletionRoutine-still-ours check is the guard against
			// double-patching -- it only fires when the walk was interrupted
			// below us (STATUS_MORE_PROCESSING_REQUIRED) and our completion
			// routine never ran. a pended IRP is never touched here: its
			// completion fires later and owns the patch.
			if ( have_input && property_id == k_property_storage_device
				&& NT_SUCCESS( status )
				&& !irp->PendingReturned
				&& irp->IoStatus.Status == status
				&& stack->CompletionRoutine == disk_query_completion ) {
				__try {
					( void )patch_descriptor_serial( irp );
				}
				__except ( EXCEPTION_EXECUTE_HANDLER ) {
					// never fail disk io because of the spoof: the irp is
					// already complete either way
				}
			}
			return status;
		}

		bool install_ioctl_hook( ) {
			if ( g_disk_ioctl_original )
				return true; // one-shot: repeated op-17 never re-hooks

			// runtime-resolved exports -- zero new import-table entries
			const auto ob_ref_address = kernel::get_export(
				kernel::m_ntoskrnl_base, oxorany( "ObReferenceObjectByName" ) );
			const auto io_driver_object_type_address = kernel::get_export(
				kernel::m_ntoskrnl_base, oxorany( "IoDriverObjectType" ) );
			if ( !ob_ref_address || !io_driver_object_type_address )
				return false;

			// IoDriverObjectType is an exported DATA pointer: the export
			// address holds the POBJECT_TYPE value
			auto* io_driver_object_type =
				*reinterpret_cast< void** >( io_driver_object_type_address );
			if ( !io_driver_object_type )
				return false;

			using ob_reference_object_by_name_t = NTSTATUS( * )(
				PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK,
				POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID* );
			auto ob_reference_object_by_name = reinterpret_cast<
				ob_reference_object_by_name_t >( ob_ref_address );

			UNICODE_STRING driver_name{ };
			RtlInitUnicodeString( &driver_name, L"\\Driver\\Disk" );
			PDRIVER_OBJECT driver_object = nullptr;
			const auto status = ob_reference_object_by_name(
				&driver_name, OBJ_CASE_INSENSITIVE, nullptr, 0,
				static_cast< POBJECT_TYPE >( io_driver_object_type ),
				KernelMode, nullptr, reinterpret_cast< PVOID* >( &driver_object ) );
			if ( status < 0 || !driver_object )
				return false;

			// paranoia before touching a dispatch table: the object must be
			// a driver object (IO_TYPE_DRIVER = 4) with a live device-control
			// entry
			if ( driver_object->Type != 4
				|| driver_object->Size < sizeof( DRIVER_OBJECT )
				|| !driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] ) {
				kernel::obf_dereference_object( driver_object );
				return false;
			}

			auto* current = driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ];

			// publish the original BEFORE the hook becomes reachable: a
			// thread can enter disk_ioctl_hook the instruction after the
			// swap, and it dereferences g_disk_ioctl_original immediately
			g_disk_ioctl_original = current;

			// swap only if unchanged since it was read -- a concurrent hook
			// racer must win or lose atomically, never interleave
			auto* swapped = InterlockedCompareExchangePointer(
				reinterpret_cast< PVOID* >(
					&driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] ),
				reinterpret_cast< PVOID >( disk_ioctl_hook ),
				current );
			if ( swapped != current ) {
				g_disk_ioctl_original = nullptr;
				kernel::obf_dereference_object( driver_object );
				return false;
			}

			// the object reference is deliberately held for the boot: the
			// hook keeps calling into disk.sys's dispatch and must never let
			// the driver unload underneath it (disk.sys is a boot driver and
			// never unloads in practice -- the pinned reference removes even
			// the theoretical race)
			return true;
		}

	} // anonymous namespace

	bool install( ) {
		// one-shot per install: a repeated op-17 dispatch is a no-op (the
		// serial/hook latches below guard the desync-sensitive surfaces; this
		// latch guards the GUID/ProductId registry group too, so nothing
		// re-mutates). a fresh launch maps a fresh image with a fresh nonce
		// and draws a fresh identity -- that rotation is by design.
		static bool s_done = false;
		static bool s_result = false;
		if ( s_done )
			return s_result;
		s_done = true;
		s_result = false;

		const auto scsi_ok = patch_scsi_devicemap( );
		const auto mounted_ok = patch_mounted_devices( );
		const auto hwcfg_ok = patch_hardware_config( );
		const auto machine_ok = patch_machine_guid( );
		const auto pid_ok = patch_product_id( );
		const auto hook_ok = install_ioctl_hook( );
		s_result = scsi_ok || mounted_ok || hwcfg_ok || machine_ok || pid_ok || hook_ok;

		// per-stage report (bit layout in comm/spoof_stages.h) -- a hook
		// install that failed now shows up as hook=FAIL in the loader line
		// instead of silently counting toward a generic ok
		spoof::mark_stage( spoof::stages::disk_devicemap_reg, scsi_ok );
		spoof::mark_stage( spoof::stages::machineguid_productid,
			machine_ok || pid_ok );
		spoof::mark_stage( spoof::stages::disk_ioctl_hook_install, hook_ok );
		return s_result;
	}

} // namespace spoof::disk