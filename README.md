# Advanced Fellowship Management System

An enterprise-grade, memory-safe C implementation of a dynamic member management system. It utilizes a **hybrid data structure** combining an ordered Doubly Linked List (DLL) with a Hash Table index to achieve both $O(N)$ ordered traversal and $O(1)$ average-time lookups.

## 🏗️ Architecture

- **Primary Storage:** A Doubly Linked List maintained in strict alphabetical order by member name.
- **Secondary Index:** A separate-chaining Hash Table (FNV-1a 64-bit) mapping names directly to DLL nodes for instant access.
- **Memory Safety:** Implements a custom `AVAIL` node pool to recycle memory instead of frequent `malloc/free` cycles.
- **Security:** Sensitive data (names/races) is securely zeroed out (`secure_wipe`) before nodes are recycled or deallocated to prevent data remanence.
- **State Management:** Includes a 3-level Undo stack using the Command Pattern to reverse Add/Remove operations.
- **Persistence:** Binary serialization with CRC32 integrity checking and magic number validation.

## 🚀 Compilation

Requires GCC with AddressSanitizer for development/debugging:

```bash
gcc -Wall -Wextra -O3 -fsanitize=address -g -o fellowship fellowship.c
