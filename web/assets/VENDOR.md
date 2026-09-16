# Vendored admin UI assets

The admin UI is Vue 3 + Ant Design Vue 4 **without a bundler** (mon-server.md
§9.1): these UMD builds are embedded into the binary with `go:embed` and served
from `/admin/assets/`. The Go build stays Node-free — nothing here is compiled.

| file | package | version | source |
|---|---|---|---|
| `vue.global.prod.js` | `vue` | 3.5.13 | npm registry tarball, `dist/vue.global.prod.js` |
| `antd.min.js` | `ant-design-vue` | 4.2.6 | npm registry tarball, `dist/antd.min.js` |
| `antd.min.js.LICENSE.txt` | `ant-design-vue` | 4.2.6 | licence banner shipped with the build |
| `reset.css` | `ant-design-vue` | 4.2.6 | `dist/reset.css` |
| `dayjs.min.js` | `dayjs` | 1.11.13 | `dayjs.min.js` |
| `dayjs.relativeTime.js` | `dayjs` | 1.11.13 | `plugin/relativeTime.js`, for the "N ago" columns |

Ant Design Vue 4 is CSS-in-JS: there is **no** `antd.min.css` to vendor. The
component styles are injected at runtime by `antd.min.js`; `reset.css` is the
only stylesheet the package ships, and the theme (`colorPrimary #008771`, dark
algorithm) is applied through `ConfigProvider`.

To refresh a file: `npm pack <package>@<version>` and copy the path above out of
the tarball. Update the version in this table in the same change.
