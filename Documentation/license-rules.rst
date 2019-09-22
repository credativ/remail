.. SPDX-License-Identifier: GPL-2.0

.. _remail_licensing_rules:

remail licensing rules
======================

The remail project is provided under the terms of the GNU General Public
License version 2 only (GPL-2.0-only), as provided in LICENSES/GPL-2.0.

This documentation file provides a description of how each source file
should be annotated to make its license clear and unambiguous.
It doesn't replace the projects license.

The license described in the COPYING file applies to the project source
as a whole, though individual source files can have a different license
which is required to be compatible with the GPL-2.0-only::

    GPL-2.0-or-later  :  GNU General Public License v2.0 or later

Aside from that, individual files can be provided under a dual license,
e.g. one of the compatible GPL variants and alternatively under a
permissive license like BSD, MIT etc.

The common way of expressing the license of a source file is to add the
matching boilerplate text into the top comment of the file.  Due to
formatting, typos etc. these "boilerplates" are hard to validate for
tools which are used in the context of license compliance.

An alternative to boilerplate text is the use of Software Package Data
Exchange (SPDX) license identifiers in each source file.  SPDX license
identifiers are machine parsable and precise shorthands for the license
under which the content of the file is contributed.  SPDX license
identifiers are managed by the SPDX Workgroup at the Linux Foundation and
have been agreed on by partners throughout the industry, tool vendors, and
legal teams.  For further information see https://spdx.org/

The remail prokect requires the precise SPDX identifier in all source
files.  The valid identifiers used in the remail project are explained in
the section `License identifiers`_ and have been retrieved from the
official SPDX license list at https://spdx.org/licenses/ along with the
license texts.

License identifier syntax
-------------------------

1. Placement:

   The SPDX license identifier in source files shall be added at the first
   possible line in a file which can contain a comment.  For the majority
   or files this is the first line, except for executable scripts which
   require the '#!PATH_TO_INTERPRETER' in the first line.  For those
   scripts the SPDX identifier goes into the second line.

|

2. Style:

   The SPDX license identifier is added in form of a comment.  The comment
   style depends on the file type::

      scripts:	# SPDX-License-Identifier: <SPDX License Expression>
      .py:	# SPDX-License-Identifier: <SPDX License Expression>
      .rst:	.. SPDX-License-Identifier: <SPDX License Expression>

|

3. Syntax:

   A <SPDX License Expression> is either an SPDX short form license
   identifier found on the SPDX License List. When multiple licenses apply,
   an expression consists of keywords "AND", "OR" separating
   sub-expressions and surrounded by "(", ")" .

   License identifiers for licenses like [L]GPL with the 'or later' option
   are constructed by using a "-or-later" for indicating the 'or later'
   option.::

      # SPDX-License-Identifier: GPL-2.0-or-later

   OR should be used if the file is dual licensed and only one license is
   to be selected.  For example::

      # SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause

   AND should be used if the file has multiple licenses whose terms all
   apply to use the file. For example, if code is inherited from another
   project and permission has been given to put it in the remail project,
   but the original license terms need to remain in effect::

      # SPDX-License-Identifier: GPL-2.0-only AND MIT

     
License identifiers
-------------------

The licenses currently used, as well as the licenses for code added to the
project can be found in the LICENSES directory.

Whenever possible these licenses should be used as they are known to be
fully compatible and widely used.

The files in this directory contain the full license text and metatags.
The file names are identical to the SPDX license identifier which shall be
used for the license in source files.

Examples::

   LICENSES/GPL-2.0

Contains the GPL version 2 license text and the required metatags:

Metatags:

  The following meta tags must be available in a license file:

   - Valid-License-Identifier:

     One or more lines which declare which License Identifiers are valid
     inside the project to reference this particular license text.  Usually
     this is a single valid identifier, but e.g. for licenses with the 'or
     later' options two identifiers are valid.

   - SPDX-URL:

     The URL of the SPDX page which contains additional information related
     to the license.

   - Usage-Guidance:

     Freeform text for usage advice. The text must include correct examples
     for the SPDX license identifiers as they should be put into source
     files according to the `License identifier syntax`_ guidelines.

   - License-Text:

     All text after this tag is treated as the original license text

   File format examples::

      Valid-License-Identifier: GPL-2.0-only
      Valid-License-Identifier: GPL-2.0-or-later
      SPDX-URL: https://spdx.org/licenses/GPL-2.0-only.html
      Usage-Guide:
        To use this license in source code, put one of the following SPDX
	tag/value pairs into a comment according to the placement
	guidelines in the licensing rules documentation.
	For 'GNU General Public License (GPL) version 2 only' use:
	  SPDX-License-Identifier: GPL-2.0-only
	For 'GNU General Public License (GPL) version 2 or any later version' use:
	  SPDX-License-Identifier: GPL-2.0-or-later
      License-Text:
        Full license text

|

All SPDX license identifiers must have a corresponding file in the LICENSE
subdirectory. This is required to allow tool verification and to have the
licenses ready to read and extract right from the source, which is
recommended by various FOSS organizations, e.g. the `FSFE REUSE initiative
<https://reuse.software/>`_.
