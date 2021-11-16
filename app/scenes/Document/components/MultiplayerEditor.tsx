import { HocuspocusProvider, WebSocketStatus } from "@hocuspocus/provider";
import * as React from "react";
import { useTranslation } from "react-i18next";
import { useHistory } from "react-router-dom";
import { IndexeddbPersistence } from "y-indexeddb";
import * as Y from "yjs";
import Editor, { Props as EditorProps } from "components/Editor";
import env from "env";
import useCurrentToken from "hooks/useCurrentToken";
import useCurrentUser from "hooks/useCurrentUser";
import useIdle from "hooks/useIdle";
import useIsMounted from "hooks/useIsMounted";
import usePageVisibility from "hooks/usePageVisibility";
import useStores from "hooks/useStores";
import useToasts from "hooks/useToasts";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'multiplayer/MultiplayerExtensi... Remove this comment to see the full error message
import MultiplayerExtension from "multiplayer/MultiplayerExtension";
// @ts-expect-error ts-migrate(2307) FIXME: Cannot find module 'utils/routeHelpers' or its cor... Remove this comment to see the full error message
import { homePath } from "utils/routeHelpers";

type Props = EditorProps & {
  id: string;
  onSynced?: () => void;
};

function MultiplayerEditor({ onSynced, ...props }: Props, ref: any) {
  const documentId = props.id;
  const history = useHistory();
  const { t } = useTranslation();
  const currentUser = useCurrentUser();
  const { presence, ui } = useStores();
  const token = useCurrentToken();
  const [showCursorNames, setShowCursorNames] = React.useState(false);
  const [remoteProvider, setRemoteProvider] = React.useState();
  const [isLocalSynced, setLocalSynced] = React.useState(false);
  const [isRemoteSynced, setRemoteSynced] = React.useState(false);
  const [ydoc] = React.useState(() => new Y.Doc());
  const { showToast } = useToasts();
  const isIdle = useIdle();
  const isVisible = usePageVisibility();
  const isMounted = useIsMounted();
  // Provider initialization must be within useLayoutEffect rather than useState
  // or useMemo as both of these are ran twice in React StrictMode resulting in
  // an orphaned websocket connection.
  // see: https://github.com/facebook/react/issues/20090#issuecomment-715926549
  React.useLayoutEffect(() => {
    const debug = env.ENVIRONMENT === "development";
    const name = `document.${documentId}`;
    const localProvider = new IndexeddbPersistence(name, ydoc);
    const provider = new HocuspocusProvider({
      url: `${env.COLLABORATION_URL}/collaboration`,
      // @ts-expect-error ts-migrate(2345) FIXME: Argument of type '{ url: string; debug: boolean; n... Remove this comment to see the full error message
      debug,
      name,
      document: ydoc,
      token,
      maxReconnectTimeout: 10000,
    });
    provider.on("authenticationFailed", () => {
      showToast(
        t(
          "Sorry, it looks like you don’t have permission to access the document"
        )
      );
      history.replace(homePath());
    });
    // @ts-expect-error ts-migrate(7031) FIXME: Binding element 'states' implicitly has an 'any' t... Remove this comment to see the full error message
    provider.on("awarenessChange", ({ states }) => {
      // @ts-expect-error ts-migrate(7031) FIXME: Binding element 'user' implicitly has an 'any' typ... Remove this comment to see the full error message
      states.forEach(({ user, cursor }) => {
        if (user) {
          // could know if the user is editing here using `state.cursor` but it
          // feels distracting in the UI, once multiplayer is on for everyone we
          // can stop diffentiating
          presence.touch(documentId, user.id, !!cursor);
        }
      });
    });

    const showCursorNames = () => {
      setShowCursorNames(true);
      setTimeout(() => {
        if (isMounted()) {
          setShowCursorNames(false);
        }
      }, 2000);
      provider.off("awarenessChange", showCursorNames);
    };

    provider.on("awarenessChange", showCursorNames);
    localProvider.on("synced", () =>
      // only set local storage to "synced" if it's loaded a non-empty doc
      setLocalSynced(!!ydoc.get("default")._start)
    );
    provider.on("synced", () => {
      presence.touch(documentId, currentUser.id, false);
      setRemoteSynced(true);
    });

    if (debug) {
      // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'ev' implicitly has an 'any' type.
      provider.on("status", (ev) => console.log("status", ev.status));
      // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'ev' implicitly has an 'any' type.
      provider.on("message", (ev) => console.log("incoming", ev.message));
      // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'ev' implicitly has an 'any' type.
      provider.on("outgoingMessage", (ev) =>
        console.log("outgoing", ev.message)
      );
      // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'ev' implicitly has an 'any' type.
      localProvider.on("synced", (ev) => console.log("local synced"));
    }

    // @ts-expect-error ts-migrate(7006) FIXME: Parameter 'ev' implicitly has an 'any' type.
    provider.on("status", (ev) => ui.setMultiplayerStatus(ev.status));
    // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'HocuspocusProvider' is not assig... Remove this comment to see the full error message
    setRemoteProvider(provider);
    return () => {
      provider?.destroy();
      localProvider?.destroy();
      // @ts-expect-error ts-migrate(2345) FIXME: Argument of type 'null' is not assignable to param... Remove this comment to see the full error message
      setRemoteProvider(null);
      ui.setMultiplayerStatus(undefined);
    };
  }, [
    history,
    showToast,
    t,
    documentId,
    ui,
    presence,
    token,
    ydoc,
    currentUser.id,
  ]);
  const user = React.useMemo(() => {
    return {
      id: currentUser.id,
      name: currentUser.name,
      color: currentUser.color,
    };
  }, [currentUser.id, currentUser.color, currentUser.name]);
  const extensions = React.useMemo(() => {
    if (!remoteProvider) {
      return [];
    }

    return [
      new MultiplayerExtension({
        user,
        provider: remoteProvider,
        document: ydoc,
      }),
    ];
  }, [remoteProvider, user, ydoc]);
  React.useEffect(() => {
    if (isLocalSynced && isRemoteSynced) {
      onSynced?.();
    }
  }, [onSynced, isLocalSynced, isRemoteSynced]);
  // Disconnect the realtime connection while idle. `isIdle` also checks for
  // page visibility and will immediately disconnect when a tab is hidden.
  React.useEffect(() => {
    if (!remoteProvider) {
      return;
    }

    if (
      isIdle &&
      !isVisible &&
      // @ts-expect-error ts-migrate(2532) FIXME: Object is possibly 'undefined'.
      remoteProvider.status === WebSocketStatus.Connected
    ) {
      // @ts-expect-error ts-migrate(2532) FIXME: Object is possibly 'undefined'.
      remoteProvider.disconnect();
    }

    if (
      (!isIdle || isVisible) &&
      // @ts-expect-error ts-migrate(2532) FIXME: Object is possibly 'undefined'.
      remoteProvider.status === WebSocketStatus.Disconnected
    ) {
      // @ts-expect-error ts-migrate(2532) FIXME: Object is possibly 'undefined'.
      remoteProvider.connect();
    }
  }, [remoteProvider, isIdle, isVisible]);

  if (!extensions.length) {
    return null;
  }

  // while the collaborative document is loading, we render a version of the
  // document from the last text cache in read-only mode if we have it.
  const showCache = !isLocalSynced && !isRemoteSynced;
  return (
    <>
      {showCache && (
        // @ts-expect-error ts-migrate(2322) FIXME: Type '{ defaultValue: string | undefined; readOnly... Remove this comment to see the full error message
        <Editor defaultValue={props.defaultValue} readOnly ref={ref} />
      )}
      <Editor
        {...props}
        value={undefined}
        defaultValue={undefined}
        extensions={extensions}
        ref={showCache ? undefined : ref}
        style={
          showCache
            ? {
                display: "none",
              }
            : undefined
        }
        className={showCursorNames ? "show-cursor-names" : undefined}
      />
    </>
  );
}

export default React.forwardRef<typeof MultiplayerEditor, any>(
  MultiplayerEditor
);