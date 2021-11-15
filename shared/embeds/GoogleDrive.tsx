import * as React from "react";
import Frame from "./components/Frame";
import Image from "./components/Image";

const URL_REGEX = new RegExp("^https?://drive.google.com/file/d/(.*)$");
type Props = {
  attrs: {
    href: string;
    matches: string[];
  };
};

export default class GoogleDrive extends React.Component<Props> {
  static ENABLED = [URL_REGEX];

  override render() {
    return (
      <Frame
        src={this.props.attrs.href.replace("/view", "/preview")}
        icon={
          <Image
            src="/images/google-drive.png"
            alt="Google Drive Icon"
            width={16}
            height={16}
          />
        }
        title="Google Drive"
        canonicalUrl={this.props.attrs.href}
        border
      />
    );
  }
}
