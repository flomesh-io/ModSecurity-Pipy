# ModSecurity Pipy Connector

![](modsec-pipy.jpg)

The `ModSecurity-pipy` connector is the connection between [Pipy](https://github.com/flomesh-io/pipy) and [libmodsecurity](https://github.com/SpiderLabs/ModSecurity) (ModSecurity v3). This Pipy [Native Module Interface (NMI)](https://flomesh.io/pipy/docs/en/reference/pjs/3-nmi) module provides a communication channel between Pipy and libmodsecurity. This connector is required to use LibModSecurity with Pipy.

`ModSecurity-pipy` takes the form of Pipy Native Module (NMI). This module simply servers as a layer of communication between Pipy and ModSecurity.

> Note: This module depends on libmodsecurity rather than ModSecurity (version 2.9 or less).


## Compilation

Before compiling this NMI module make sure you have libmodsecurity installed. You can download it from the [ModSecurity git repo](https://github.com/SpiderLabs/ModSecurity). For information pertaining to the compilation and installation of libmodsecurity please consult the documentation provided along with it.

With libmodsecurity installed, you can proceed with the compilation of the ModSecurity-pipy connector, which follows the Pipy Native module installation procedure. From the module source directory:

> Make sure you adjust `Makefile` with location where you have installed `libmodsecurity` and dependencies it has been compiled with.


```sh
make
```

## Usage

ModSecurity for Pipy exports below PJS variables to be used from Pipy PJS script.

* __msc_inbound: PJS object which should contain the `__inbound` object properties
* __msc_intervention: PJS object, with properties `status`, `url`, `log`, `disruptive`. This object is populated by NMI module
* __msc_warnings: PJS array, all ModSecurity transaction related warnings will be populated into this var
* __msc_rules_file: String, Use this variable to set the ModSecurity Rules File name
* __msc_rules_remote: PJS Object, with properties `key`, and `url`, if you want to load ModSecurity Rules from remote URL
* __msc_rules: String, You can provide ModSecurity rules as a String
* __msc_transaction_id: String, you can pass any transaction id for tracing purposes.

#### __msc_inbound

 Populate this object with properties from `__inbound` object.

```Javascript
  .onStart(() => (
          __msc_inbound = {...__inbound},
  ))
```
 
#### __msc_intervention

 NMI module populate this Object after performing ModSecurity rules scanning on Connection, URI, Request Headers, Request Body, Response Headers, and Response Body.
 Structure of this PJS object as follows:

 * `disruptive` Boolean flag, when set indicates a disruptive action.
 * `status` Number, contains the status code. Status code of 200 indicates success
 * `url` String, either `undefined` or contains the URL which should be followed to perform re-direction. 
 * `log` String, either `undefined` or contains the log description generated from rule which caused this disruption.


#### __msc_rules_file

  Specifies the location of the modsecurity configuration file, e.g:

```Javascript
  .onStart(() => (
          __msc_inbound = {...__inbound},
          __msc_warnings = [],
          __msc_rules_file = 'modsecurity.conf'
  ))
```

#### __msc_rules_remote

Specifies from where (on the internet) a modsecurity configuration file will be downloaded. It also specifies the key that will be used to authenticate to that server:

```Javascript
  .onStart(() => (
          __msc_inbound = {...__inbound},
          __msc_warnings = [],
          __msc_rules_remote = {
            key: 'my-server-key', 
            url: 'https://my-own-server/rules/download'
          }
  ))
```

#### __msc_rules

Allows for the direct inclusion of a ModSecurity rule into the Pipy pipeline:

```Javascript
  .onStart(() => (
    __msc_inbound = {...__inbound},
    __msc_warnings = [],
    __msc_rules = `
    SecRuleEngine On
    SecResponseBodyAccess On
    SecDebugLog modsec_debug.log
    SecDebugLogLevel 9
    SecRuleRemoveById 10
    SecStatusEngine On    
    `
  ))
```

#### __msc_transaction_id

Allows to pass transaction ID from Pipy instead of generating it in the library. This can be useful for tracing purposes, e.g. consider this configuration:

```Javascript
  .onStart(() => (
          __msc_inbound = {...__inbound},
          __msc_warnings = [],
          __msc_rules_file = 'modsecurity.conf',
          __msc_transaction_id = 'host:port-transaction-id'
  ))
```

### Sample PJS

```Javascript
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
        .onStart(() => (
          __msc_inbound = {...__inbound},
          __msc_warnings = [],
          __msc_rules = `
          SecRuleEngine On
          SecResponseBodyAccess On
          SecDebugLog modsec_debug.log
          SecDebugLogLevel 9
          SecRuleRemoveById 10
          SecStatusEngine On
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
              $=>$.connect('upstream-service:port')
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
        )
      )
      .handleMessageEnd(() =>  __msc_warnings.forEach(w => console.log(w)))
  )

```