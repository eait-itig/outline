import { observable } from "mobx";
import { observer, inject } from "mobx-react";
import { MenuIcon } from "outline-icons";
import * as React from "react";
import { Helmet } from "react-helmet";
import { withTranslation } from "react-i18next";
// @ts-expect-error ts-migrate(2305) FIXME: Module '"react-router-dom"' has no exported member... Remove this comment to see the full error message
import { RouterHistory } from "react-router-dom";
import { Switch, Route, withRouter } from "react-router-dom";
import styled from "styled-components";
import breakpoint from "styled-components-breakpoint";
import AuthStore from "stores/AuthStore";
import DocumentsStore from "stores/DocumentsStore";
import PoliciesStore from "stores/PoliciesStore";
import UiStore from "stores/UiStore";
import ErrorSuspended from "scenes/ErrorSuspended";
import Button from "components/Button";
import Flex from "components/Flex";
import { LoadingIndicatorBar } from "components/LoadingIndicator";
import RegisterKeyDown from "components/RegisterKeyDown";
import Sidebar from "components/Sidebar";
import SettingsSidebar from "components/Sidebar/Settings";
import SkipNavContent from "components/SkipNavContent";
import SkipNavLink from "components/SkipNavLink";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'utils/keyboard' or its corresp... Remove this comment to see the full error message
import { isModKey } from "utils/keyboard";
import {
  searchUrl,
  matchDocumentSlug as slug,
  newDocumentPath,
  settingsPath,
  // @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'utils/routeHelpers' or its cor... Remove this comment to see the full error message
} from "utils/routeHelpers";

const DocumentHistory = React.lazy(
  () =>
    import(
      /* webpackChunkName: "document-history" */
      "components/DocumentHistory"
    )
);
const CommandBar = React.lazy(
  () =>
    import(
      /* webpackChunkName: "command-bar" */
      "components/CommandBar"
    )
);
type Props = {
  documents: DocumentsStore;
  children?: React.ReactNode | null | undefined;
  actions?: React.ReactNode | null | undefined;
  title?: React.ReactNode | null | undefined;
  auth: AuthStore;
  ui: UiStore;
  history: RouterHistory;
  policies: PoliciesStore;
  notifications?: React.ReactNode;
};

@observer
class Layout extends React.Component<Props> {
  scrollable: HTMLDivElement | null | undefined;

  @observable
  keyboardShortcutsOpen = false;

  goToSearch = (ev: KeyboardEvent) => {
    ev.preventDefault();
    ev.stopPropagation();
    this.props.history.push(searchUrl());
  };

  goToNewDocument = () => {
    const { activeCollectionId } = this.props.ui;
    if (!activeCollectionId) return;
    const can = this.props.policies.abilities(activeCollectionId);
    if (!can.update) return;
    this.props.history.push(newDocumentPath(activeCollectionId));
  };

  render() {
    const { auth, ui } = this.props;
    const { user, team } = auth;
    const showSidebar = auth.authenticated && user && team;
    const sidebarCollapsed = ui.isEditing || ui.sidebarCollapsed;
    if (auth.isSuspended) return <ErrorSuspended />;
    return (
      <Container column auto>
        <RegisterKeyDown trigger="n" handler={this.goToNewDocument} />
        <RegisterKeyDown trigger="t" handler={this.goToSearch} />
        <RegisterKeyDown trigger="/" handler={this.goToSearch} />
        <RegisterKeyDown
          trigger="."
          handler={(event) => {
            if (isModKey(event)) {
              ui.toggleCollapsedSidebar();
            }
          }}
        />
        <Helmet>
          <title>{team && team.name ? team.name : "Outline"}</title>
          <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
          />
        </Helmet>
        <SkipNavLink />

        {this.props.ui.progressBarVisible && <LoadingIndicatorBar />}
        {this.props.notifications}

        <MobileMenuButton
          // @ts-expect-error ts-migrate(2769) FIXME: No overload matches this call.
          onClick={ui.toggleMobileSidebar}
          icon={<MenuIcon />}
          iconColor="currentColor"
          neutral
        />

        <Container auto>
          {showSidebar && (
            <Switch>
              <Route path={settingsPath()} component={SettingsSidebar} />
              <Route component={Sidebar} />
            </Switch>
          )}

          <SkipNavContent />
          <Content
            auto
            justify="center"
            // @ts-expect-error ts-migrate(2769) FIXME: No overload matches this call.
            $isResizing={ui.sidebarIsResizing}
            $sidebarCollapsed={sidebarCollapsed}
            style={
              sidebarCollapsed
                ? undefined
                : {
                    marginLeft: `${ui.sidebarWidth}px`,
                  }
            }
          >
            {this.props.children}
          </Content>

          <React.Suspense fallback={null}>
            <Switch>
              <Route
                path={`/doc/${slug}/history/:revisionId?`}
                component={DocumentHistory}
              />
            </Switch>
          </React.Suspense>
        </Container>
        <CommandBar />
      </Container>
    );
  }
}

const Container = styled(Flex)`
  background: ${(props) => props.theme.background};
  transition: ${(props) => props.theme.backgroundTransition};
  position: relative;
  width: 100%;
  min-height: 100%;
`;
const MobileMenuButton = styled(Button)`
  position: fixed;
  top: 12px;
  left: 12px;
  z-index: ${(props) => props.theme.depths.sidebar - 1};

  ${breakpoint("tablet")`
    display: none;
  `};

  @media print {
    display: none;
  }
`;
const Content = styled(Flex)`
  margin: 0;
  transition: ${(props) =>
    // @ts-expect-error ts-migrate(2339) FIXME: Property '$isResizing' does not exist on type 'The... Remove this comment to see the full error message
    props.$isResizing ? "none" : `margin-left 100ms ease-out`};

  @media print {
    margin: 0 !important;
  }

  ${breakpoint("mobile", "tablet")`
    margin-left: 0 !important;
  `}

  ${breakpoint("tablet")`
    // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'props' implicitly has an 'any' type.
    ${(props) =>
      props.$sidebarCollapsed &&
      `margin-left: ${props.theme.sidebarCollapsedWidth}px;`}
  `};
`;

// @ts-expect-error ts-migrate(2344) FIXME: Type 'Layout' does not satisfy the constraint 'Com... Remove this comment to see the full error message
export default withTranslation()<Layout>(
  // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'typeof Layout' is not assignable... Remove this comment to see the full error message
  inject("auth", "ui", "documents", "policies")(withRouter(Layout))
);