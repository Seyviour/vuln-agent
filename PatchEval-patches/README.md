# PatchEval Fixes

This directory contains patches that must be applied to the PatchEval submodule before running experiments.

## PatchEval Version

**Required Commit**: `0ec3f4b56c6d59f416d6c43e057da8d0930b7eaf`
**Commit Message**: "fix typo for programming_language"

### Verify Your PatchEval Version

Check if your PatchEval submodule is on the correct commit:

```bash
cd PatchEval
git log -1 --format="%H %s"
```

Expected output:
```
0ec3f4b56c6d59f416d6c43e057da8d0930b7eaf fix typo for programming_language
```

### Checkout Correct Version

If your PatchEval is on a different commit, checkout the required version:

```bash
cd PatchEval
git checkout 0ec3f4b56c6d59f416d6c43e057da8d0930b7eaf
```

## Required Patch: Temporary File Fix

**File**: `patcheval-tempfile-fix.patch`

### Problem

PatchEval's `DockerManager` class has a bug where it prematurely deletes temporary patch files in a `finally` block. This causes the Docker container to fail when trying to apply patches because the temporary file is deleted before the container can read it.

### Solution

The patch makes two changes to `patcheval/evaluation/run_evaluation.py`:

1. **Initialize `tmp_file_path` to `None`**: Prevents `UnboundLocalError` when the variable is referenced in the finally block
2. **Comment out the `finally` block**: Prevents premature deletion of the temporary patch file

The temporary files will still be cleaned up when the system exits, so there's no resource leak.

### Changes

```diff
@@ -47,6 +47,7 @@ class DockerManager:
         """
         image_name = f"ghcr.io/anonymous2578-data/{cve.lower()}:latest"
         volumes = {}
+        tmp_file_path = None
         def _create_patch_file(llm_patch):
             fd, tmp_file_path = tempfile.mkstemp(suffix='.patch')
             with os.fdopen(fd, 'w', encoding='utf-8') as tmp_file:
@@ -72,11 +73,11 @@ class DockerManager:
         except Exception as e:
             self.logger.debug(f"Failed to start container: {e}", extra={"cve": self.cve})
             return None
-        finally:
-            # clean up temp file
-            if tmp_file_path and os.path.exists(tmp_file_path):
-                os.unlink(tmp_file_path)
-                tmp_file_path = None
+        # finally:
+        #     # clean up temp file
+        #     if tmp_file_path and os.path.exists(tmp_file_path):
+        #         os.unlink(tmp_file_path)
+        #         tmp_file_path = None
```

## How to Apply

### Automatic Application

Run the provided script from the project root:

```bash
cd PatchEval-patches
./apply-patcheval-fix.sh
```

The script will:
- Check if the PatchEval directory exists
- Verify if the patch is already applied
- Apply the patch if needed
- Report success or any issues

### Manual Application

If you prefer to apply manually:

```bash
cd PatchEval
git apply ../PatchEval-patches/patcheval-tempfile-fix.patch
```

### Verification

After applying, verify the changes:

```bash
cd PatchEval
git diff patcheval/evaluation/run_evaluation.py
```

You should see the changes described above.

## Important Notes

1. **Apply before running experiments**: This patch must be applied before using the multi-agent system, otherwise patch application will fail
2. **Don't commit to PatchEval**: These changes are specific to this use case and should not be committed to the PatchEval repository
3. **Reapply after updates**: If you update the PatchEval submodule, you'll need to reapply this patch

## Troubleshooting

### Patch already applied
If you see "Patch already applied", you're good to go. No action needed.

### File has different modifications
If you see "File has different modifications", someone may have made different changes to the file. Review the changes manually:

```bash
cd PatchEval
git diff patcheval/evaluation/run_evaluation.py
```

Compare with the expected changes in `patcheval-tempfile-fix.patch`.

### Patch fails to apply
If the patch fails to apply (e.g., due to upstream changes in PatchEval):

1. Check the current state of the file
2. Manually apply the changes described above
3. Consider updating the patch file for future use
