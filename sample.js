pipy()
  .import({
    __msc_inbound: 'mod-sec',
    __msc_intervention: 'mod-sec',
    __msc_warnings: 'mod-sec',
    __msc_rules_file: 'mod-sec',
    __msc_rules_remote: 'mod-sec',
    __msc_rules: 'mod-sec',
    __msc_transaction_id: 'mod-sec',
  })
  .listen(8080)
  
  .demuxHTTP().to(
    $=>$
        .onStart(() => void(
          __msc_inbound = {...__inbound},
          __msc_warnings = [],
          //__msc_rules_file = 'modsecurity.conf',
          //__msc_rules_remote = {key: 'test', url: 'https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt'},
          __msc_rules = `
          SecRuleEngine On
          SecResponseBodyAccess On
          SecDebugLog modsec_debug.log
          SecDebugLogLevel 9
          SecRuleRemoveById 10
          SecStatusEngine On
          SecAuditEngine RelevantOnly
          SecAuditLogRelevantStatus "^(?:5|4(?!04))"

          SecAuditLogParts ABIJDEFHZ
          SecAuditLogType Serial
          SecAuditLog modsec_audit.log
          `,
          __msc_transaction_id = 'localhost:8080-tx'
        ))
        .use('./bin/modsecurity-nmi.so','request')
        .branchMessage(
          () => (__msc_intervention.disruptive), (
            $=>$.replaceMessage(()=>(
              (__msc_intervention?.log && console.log(__msc_intervention.log)),
              new Message({ status: __msc_intervention.status }, 'Forbidden' )
            ))
          ),
          () => (__msc_intervention.status && __msc_intervention.status != 200), (
            $=>$.replaceMessage(()=>(
              (__msc_intervention?.url) && console.log(`Redirecting to ${__msc_intervention.url}`),
              new Message({ status: __msc_intervention.status, 
                  location: __msc_intervention.url })
            ))             
          ),
          () => (__msc_intervention.status == 200),
          (
            $=>$.muxHTTP().to(
              $=>$.connect('localhost:8000')
            )
          )
        )
      .use('./bin/modsecurity-nmi.so','response')
      .branchMessage(
        () => (__msc_intervention.disruptive), (
          $=>$.replaceMessage(()=>(
            (__msc_intervention?.log && console.log(__msc_intervention.log)),
            new Message({ status: __msc_intervention.status }, 'Forbidden' )
          ))
        ),
        (
          $=>$
        )
      )
      .handleMessageEnd(() =>  __msc_warnings.forEach(w => console.log(w)))

  )

    .listen(8000)
    .serveHTTP(msg => new Message('hello world'))
