# Synthetic ChalkAgents–Prosperna engagement provenance

This invented record explains that ChalkAgents performs the represented work
through a Prosperna engagement for the Project 2 account.

It intentionally contains no contract terms, contacts, credentials, invoices,
or customer data. The relationship must never be interpreted as inherited
permission between the ChalkAgents organization, the engagement, the account,
or its projects.

## Conformance graph

The invented graph below is test input for the control-plane authorization
suite. It is provenance and navigation metadata only. None of its edges grant
human or agent access.

<!-- provenance-json-start -->
```json
{
  "anchor_folderbase_id": "folderbase_019f9c00-0000-7000-8000-000000000003",
  "folderbases": {
    "chalkagents": "folderbase_019f9c00-0000-7000-8000-000000000001",
    "prosperna": "folderbase_019f9c00-0000-7000-8000-000000000002",
    "project_2": "folderbase_019f9c00-0000-7000-8000-000000000003"
  },
  "workspace_id": "workspace_019f9c00-0000-7000-8000-000000000004",
  "shared_object_id": "obj_019f9c00-0000-7000-8000-000000000005",
  "commercial_object_id": "obj_019f9c00-0000-7000-8000-000000000006",
  "relationships": [
    {
      "subject": {
        "type": "folderbase",
        "id": "folderbase_019f9c00-0000-7000-8000-000000000001"
      },
      "relationship": "organization_engagement",
      "object": {
        "type": "folderbase",
        "id": "folderbase_019f9c00-0000-7000-8000-000000000002"
      }
    },
    {
      "subject": {
        "type": "folderbase",
        "id": "folderbase_019f9c00-0000-7000-8000-000000000002"
      },
      "relationship": "engagement_customer",
      "object": {
        "type": "folderbase",
        "id": "folderbase_019f9c00-0000-7000-8000-000000000003"
      }
    },
    {
      "subject": {
        "type": "workspace",
        "id": "workspace_019f9c00-0000-7000-8000-000000000004"
      },
      "relationship": "workspace_member",
      "object": {
        "type": "folderbase",
        "id": "folderbase_019f9c00-0000-7000-8000-000000000003"
      }
    },
    {
      "subject": {
        "type": "folder",
        "id": "Prosperna"
      },
      "relationship": "filesystem_parent",
      "object": {
        "type": "folder",
        "id": "Prosperna/Project 2"
      }
    },
    {
      "subject": {
        "type": "object",
        "id": "obj_019f9c00-0000-7000-8000-000000000005"
      },
      "relationship": "object_reference",
      "object": {
        "type": "object",
        "id": "obj_019f9c00-0000-7000-8000-000000000006"
      }
    }
  ]
}
```
<!-- provenance-json-end -->
