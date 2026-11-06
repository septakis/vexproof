# vexproof Pro License

Version 1.0, October 2026

Copyright (c) 2026 Brad Stevenson, who publishes vexproof under the name Septakis ("we", "us").

This license covers the **Pro Files**: every file in the `src/pro/` directory of the vexproof
repository and npm package. Every other file in vexproof is under the MIT License in the `LICENSE`
file at the top of the repository. The Pro Files are source-available, not open source.

## 1. Terms used here

**Pro Features** are the things the Pro Files do that vexproof turns on only when it finds a valid
License Key. Today they are: settling findings by checking which files of a package shipped
(including with rules you supply through `--rules`), carrying reviews forward from a baseline
(`--baseline`), the evidence report (`--report`), applying VEX to Dependabot alerts
(`vexproof dependabot`), CSAF output (`--csaf`), signing (`--sign`) and the rollup across applications
(`vexproof rollup`). Checking a signature (`vexproof verify`) and making a signing key (`vexproof keygen`)
need no License Key.

A **License Key** is a signed key we issue. A paid key names one Organization. An open-source key
names one or more public repositories. Every key has an expiry date.

An **Organization** is the single legal entity named in a paid License Key. Its employees, and
contractors while they work for it, are part of it.

## 2. What anyone may do, with or without a License Key

You may:

- download, install and keep copies of the Pro Files as part of vexproof;
- pass on unmodified copies of vexproof that include the Pro Files and this license, for example
  in a package mirror, a cache, a vendored `node_modules` folder or a container image;
- read the Pro Files;
- run vexproof with the Pro Files present. Without a License Key, vexproof uses them only to check
  for a key, to read the rules that ship with it, and to count the findings the Pro Features
  would settle. That use is allowed.

## 3. What a License Key adds

While you hold a License Key that has not expired:

- **Paid key.** The Organization may use the Pro Features on any number of products,
  repositories, machines and build runners, by any number of its people, for software it keeps
  internal and for software it ships to others.
- **Open-source key.** Anyone may use the Pro Features on the repositories named in the key, for
  as long as those repositories are public.

## 4. What is not allowed

You may not:

- use the Pro Features without a License Key that covers the use. This includes changing,
  removing or working around the key check, and calling the Pro Files from other code so as to
  get their results without a key;
- give a paid License Key to anyone outside the Organization, or publish any License Key;
- use a paid License Key to produce results for another organization's software as a service to
  it. That organization needs its own key;
- distribute changed versions of the Pro Files, or copy the Pro Files, or parts of them, into
  other software;
- remove or change the license notices in the Pro Files.

## 5. What you produce is yours

The VEX documents, reports and rules files vexproof writes for you are yours. This license puts
no conditions on them, and they stay valid and usable after your License Key expires.

## 6. When a License Key expires

A License Key ends on the date written in it. vexproof keeps the Pro Features on for 14 more days,
then runs its MIT-licensed features only. It never fails a build because a key is missing, invalid
or expired. Your rights under section 3 end with the key. Sections 2 and 5 continue.

## 7. If these terms are broken

If you break section 4, your rights under this license end. If you put it right within 30 days of
our telling you, they come back.

## 8. Changes you send us

If you send us a change to the Pro Files, for example a new module rule, you give us the right to
use it and to license it to others on any terms, and you confirm you are entitled to give it.

## 9. No warranty

vexproof gives you evidence to support your own assessment of a vulnerability. You decide what
your VEX documents say, and you are responsible for them.

THE PRO FILES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. TO THE EXTENT THE LAW ALLOWS, WE ARE NOT LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY ARISING FROM THE PRO FILES OR THEIR USE, AND OUR TOTAL LIABILITY IS LIMITED TO WHAT YOU
PAID US FOR YOUR LICENSE KEY IN THE 12 MONTHS BEFORE THE CLAIM.

## 10. Names and marks

This license gives no right to use the names "vexproof" or "Septakis" or their logos, except to
say truthfully that you use the software.

## 11. Other agreements

If you have a signed agreement with us about vexproof Pro, that agreement applies where it differs
from this license.

Questions: hello@septakis.io
