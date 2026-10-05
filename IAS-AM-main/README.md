# One maintained application

The duplicate source tree has been consolidated into the repository root.

Open the parent `IAS-AM` folder in VS Code and run:

```powershell
python -m antivirus.frontend_main
```

The useful additions from this folder now live in the root application:

- **Network** provides a read-only, asynchronous connection snapshot.
- **Settings → Monitor new downloads** enables debounced, read-only scans of stable files.

The incomplete interception proxy, packet keyword heuristic, and automatic file renaming were not suitable protection controls. The review guide explains their limitations. The original source remains in Git history at commit `0947e0d25ae686448e7cbaa068fff9604be39897`.
