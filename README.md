# Falco Rules Explorer

![index.html](img/index.png)

## Description

> This project is a WIP

Falco Rules Explorer is dashboard to explore the Falco rules in a friendly way. You can search, filter and display all details of rules.

## Configuration

The list of rules to scrape is managed by the file `registry.yaml`:

```yaml
---
rules_files:
  - "https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml"
  - "https://github.com/falcosecurity/rules/blob/main/rules/application_rules.yaml"
  - "https://github.com/falcosecurity/plugins/blob/master/plugins/k8saudit/rules/k8s_audit_rules.yaml"
  - "https://github.com/falcosecurity/plugins/blob/master/plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml"
  - "https://github.com/falcosecurity/plugins/blob/master/plugins/github/rules/github.yaml"
  - "https://github.com/falcosecurity/plugins/blob/master/plugins/okta/rules/okta_rules.yaml"
```

### Local Rule Files Support

You can also use local files instead of downloading from URLs. Use any path that's not a URL:

```yaml
---
rules_files:
  - "./my_custom_rules.yaml"     # Relative path
  - "custom/rules.yaml"          # Relative path without ./
  - "/absolute/path/rules.yaml"  # Absolute path
  - "https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml"  # Remote URL
```

The system automatically detects and supports both standard Falco rule files and merged rule files (with `info` sections) regardless of filename.

### Working with Merged Rules

Merged rule files have a special structure that includes compiled metadata. To generate merged rules from your running Falco instance:

1. **Extract and convert rules from Falco:**
```bash
falco -L 2>/dev/null | yq -P > current_rules.yaml
```

1. **Use in registry.yaml:**
```yaml
rules_files:
  - "./current_rules.yaml"  # Any filename works - format auto-detected
```

## Create the index of rules

```shell
go run .
```

It creates an `index.json` file which lists all rules with their details.

## View the dashboard

```shell
python -m http.server 3000
```

Go to http://0.0.0.0:3000/.

## Frontend

The sources for the frontend are:
- `index.html`: the dashboard
- `rule.html`: details of a rule

## Author

Thomas Labarussias (https://github.com/Issif)
