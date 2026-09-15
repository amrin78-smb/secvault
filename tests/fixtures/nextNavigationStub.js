'use strict';
// next/navigation has no router outside a Next render. The application board
// only ever calls router.refresh(), and the tests that use this stub assert
// what the board PRINTS, not where it navigates — so a no-op router is the
// whole stub. Used by tests/applicationRoutes.test.js.
module.exports = {
  useRouter: () => ({ refresh() {}, push() {}, replace() {}, back() {}, forward() {} }),
  usePathname: () => '/applications',
  useSearchParams: () => new URLSearchParams(),
  redirect() {},
  notFound() {},
};
