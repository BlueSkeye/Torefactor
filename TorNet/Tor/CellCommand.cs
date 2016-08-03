
namespace TorNet.Tor
{
    internal enum CellCommand : byte
    {
        // cell command types.
        padding = 0,
        create = 1,
        created = 2,
        relay = 3,
        destroy = 4,
        create_fast = 5,
        created_fast = 6,
        netinfo = 8,
        relay_early = 9,
        versions = 7,

        // relay command types.
        relay_begin = 1,
        relay_data = 2,
        relay_end = 3,
        relay_connected = 4,
        relay_sendme = 5,
        relay_extend = 6,
        relay_extended = 7,
        relay_truncate = 8,
        relay_truncated = 9,
        relay_drop = 10,
        relay_resolve = 11,
        relay_resolved = 12,
        relay_begin_dir = 13,

        relay_command_establish_intro = 32,
        relay_command_establish_rendezvous = 33,
        relay_command_introduce1 = 34,
        relay_command_introduce2 = 35,
        relay_command_rendezvous1 = 36,
        relay_command_rendezvous2 = 37,
        relay_command_intro_established = 38,
        relay_command_rendezvous_established = 39,
        relay_command_introduce_ack = 40,

        vpadding = 128,
        certs = 129,
        auth_challenge = 130,
        authenticate = 131,
        authorize = 132,
    }
}
