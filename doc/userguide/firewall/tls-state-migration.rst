Migrating from the old TLS state names
======================================

In this release the TLS app-layer states changed from completion
milestones to active phases: a state now describes the phase the
handshake or data exchange is *in*, and it is entered when the phase
starts rather than when it completes. The state names used in rules
(``accept:hook tls:<state>``, ``alert tls:<state>``) and in the
``firewall.policies.app.tls`` config keys were renamed accordingly, and
the flight-completion state was removed.

Old and new names
-----------------

.. list-table::
   :header-rows: 1

   * - old state (milestone)
     - new state (phase)
     - note
   * - ``client_in_progress``
     - ``client_started``
     - covers the packets before the hello
   * - ``client_hello_done``
     - ``client_hello``
     - the phase now starts at the first hello byte
   * - ``client_cert_done``
     - ``client_cert``
     -
   * - ``client_handshake_done``
     - ``client_data``
     -
   * - ``client_finished``
     - ``client_finished``
     - unchanged
   * - ``server_in_progress``
     - ``server_started``
     -
   * - ``server_hello``
     - ``server_hello``
     - unchanged
   * - ``server_cert_done``
     - ``server_cert``
     -
   * - ``server_hello_done``
     - ``server_data``
     - the flight-completion milestone no longer exists
   * - ``server_handshake_done``
     - ``server_data``
     - both map to the data phase
   * - ``server_finished``
     - ``server_finished``
     - unchanged

Semantics that changed with the rename
--------------------------------------

- The ``client_hello`` window opens at the first client-hello byte
  instead of when the hello record completes; for a fragmented hello
  the decision can be taken before the record is complete.
- ``server_data`` starts when the server flight ends and stays current
  through the data exchange; app data no longer re-enters a completion
  state.
- The ``server_hello_done`` milestone is gone. The server record
  progression between hello and data is ServerHello, the certificate
  messages, then the ChangeCipherSpec/Finished flight; the flight
  carries no inspectable data, which is why no state exists for it.
  A rule that wanted to act at "flight complete, before data" now
  belongs to the tail of ``server_cert`` or the head of
  ``server_data`` depending on intent.
- The firewall applies one decision per state: after an ``accept:hook``
  rule matches at a state, further rules at the same state are not
  evaluated. Remapping two old rules onto one new state therefore leaves
  the second one dead - keep at most one rule per state.

Migration steps
---------------

1. **Rules.** Search the ruleset for the old names
   (``client_in_progress``, ``client_hello_done``, ``client_cert_done``,
   ``client_handshake_done``, ``server_in_progress``, ``server_hello_done``,
   ``server_cert_done``, ``server_handshake_done``) and update them to
   the new names. A rule with an unknown state fails to load with a
   ``does not support hook`` error and is **not enforced**, so check the
   load output after updating.
2. **Firewall config keys.** ``firewall.policies.app.tls.<state>`` keys
   resolve against the current name table. On upgrade, a key that no
   longer matches a state is reported at load: a key known to be a
   renamed state is an error (init aborts when init-failure-fatal is
   set), other unknown keys are a warning naming the replacement.
   Update the keys, or the state falls back to the implicit default
   policy (drop in firewall mode).
3. **Monitoring.** The ``ts_progress`` field in alert events now carries
   the new state names; update any correlation on the old values.
