# Folderbase Core domain language

Folderbase Core defines the portable filesystem-native concepts shared by local
apps, agent harnesses, managed services, and remote workspaces.

## Language

**Folderbase**:
An ordinary visible root folder enhanced with stable identity, history,
agent-readable context, and one governance boundary. Its organization may evolve
without ceasing to be a normal folder.
_Avoid_: Brain, workspace database

**Folderbase Root**:
The directory containing the canonical Folderbase markers and establishing the
outer limit of one Folderbase boundary.
_Avoid_: Repository root, workspace root

**Folder Scope**:
A durable identity for a smaller folder explicitly shared from one Folderbase.
It exposes only granted content and never becomes or inherits another governance
boundary.
_Avoid_: Sub-Folderbase, inherited share

**Knowledge Object**:
A durably identified item managed by a Folderbase whose identity does not depend
on its current path.
_Avoid_: File record, path record

**Object Version**:
One immutable exact representation of a Knowledge Object, identified by the existing
object-level `VersionId` namespace.
_Avoid_: Folderbase Version, file revision

**Path Binding**:
The current association between one portable path, one stable Knowledge Object, and
the exact Object Version needed for content-bearing kinds.
_Avoid_: Filename identity, directory entry

**Folderbase Version**:
One sealed, portable full-state view of a Folderbase boundary, with its own identity
distinct from every Object Version.
_Avoid_: Snapshot file, Object Version

**Local Head**:
A device-local pointer to the Folderbase Version currently selected for one exact
Folderbase Root; it is not shared authority or a Cloud head.
_Avoid_: Remote Head, latest version

**Capture Plan**:
An opaque, bounded, device-local inventory of filesystem metadata bound to one
attested Folderbase Root, its effective ignore policy, and its optional Local Head.
It is not a sealed Folderbase Version and carries no mutation authority.
_Avoid_: Snapshot, pending version

**Tombstone**:
A retained deletion of a Path Binding whose containing Folderbase Version
establishes the deletion generation so replicas do not silently resurrect removed
state.
_Avoid_: Trash item, missing file

**Template**:
Optional versioned data that proposes starting or additive structure. It records
provenance but never becomes continuing layout authority.
_Avoid_: Schema, required taxonomy

**Organization Skill**:
Portable agent guidance for understanding and proposing how a Folderbase should
evolve. It has no authority to mutate content by itself.
_Avoid_: Organizer daemon, template engine

**Reorganization Plan**:
A sealed, digest-bound proposal for a recoverable structural change to an existing
Folderbase.
_Avoid_: Migration script, agent command

**Reorganization Draft**:
An inert, revisable record of analysis, unanswered consequential questions, answers,
and proposed rationale that may later be sealed into a Reorganization Plan.
_Avoid_: Approved plan, agent instructions

**Analysis Scope**:
The Core-required operation closure plus caller-declared portable paths and
protocol records read or affected by a Reorganization Plan and therefore required
to remain unchanged.
_Avoid_: Context window, selected files

**Consequential Question**:
A user decision whose answer can materially change a proposed organization,
boundary, narrative, or destructive outcome.
_Avoid_: Clarification prompt, form field

**Canonical Narrative**:
A current human- and agent-readable account, used when helpful, that reconciles one
related draft, proposal, topic, or decision family without deleting its evidence.
_Avoid_: Generated summary, transcript

**Nested Folderbase**:
An independent Folderbase discovered inside another filesystem tree. It is a
separate governance boundary and never inherits parent authority.
_Avoid_: Subfolder, child workspace
