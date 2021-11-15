import * as React from "react";

type Props = {
  color?: string;
};
export default function SlackIcon({ color = "#4E5C6E" }: Props) {
  return (
    <svg
      fill={color}
      width="24px"
      height="24px"
      viewBox="0 0 24 24"
      version="1.1"
    >
      <path d="M7.36156352,14.1107492 C7.36156352,15.0358306 6.60586319,15.7915309 5.68078176,15.7915309 C4.75570033,15.7915309 4,15.0358306 4,14.1107492 C4,13.1856678 4.75570033,12.4299674 5.68078176,12.4299674 L7.36156352,12.4299674 L7.36156352,14.1107492 Z M8.20846906,14.1107492 C8.20846906,13.1856678 8.96416938,12.4299674 9.88925081,12.4299674 C10.8143322,12.4299674 11.5700326,13.1856678 11.5700326,14.1107492 L11.5700326,18.3192182 C11.5700326,19.2442997 10.8143322,20 9.88925081,20 C8.96416938,20 8.20846906,19.2442997 8.20846906,18.3192182 C8.20846906,18.3192182 8.20846906,14.1107492 8.20846906,14.1107492 Z M9.88925081,7.36156352 C8.96416938,7.36156352 8.20846906,6.60586319 8.20846906,5.68078176 C8.20846906,4.75570033 8.96416938,4 9.88925081,4 C10.8143322,4 11.5700326,4.75570033 11.5700326,5.68078176 L11.5700326,7.36156352 L9.88925081,7.36156352 Z M9.88925081,8.20846906 C10.8143322,8.20846906 11.5700326,8.96416938 11.5700326,9.88925081 C11.5700326,10.8143322 10.8143322,11.5700326 9.88925081,11.5700326 L5.68078176,11.5700326 C4.75570033,11.5700326 4,10.8143322 4,9.88925081 C4,8.96416938 4.75570033,8.20846906 5.68078176,8.20846906 C5.68078176,8.20846906 9.88925081,8.20846906 9.88925081,8.20846906 Z M16.6384365,9.88925081 C16.6384365,8.96416938 17.3941368,8.20846906 18.3192182,8.20846906 C19.2442997,8.20846906 20,8.96416938 20,9.88925081 C20,10.8143322 19.2442997,11.5700326 18.3192182,11.5700326 L16.6384365,11.5700326 L16.6384365,9.88925081 Z M15.7915309,9.88925081 C15.7915309,10.8143322 15.0358306,11.5700326 14.1107492,11.5700326 C13.1856678,11.5700326 12.4299674,10.8143322 12.4299674,9.88925081 L12.4299674,5.68078176 C12.4299674,4.75570033 13.1856678,4 14.1107492,4 C15.0358306,4 15.7915309,4.75570033 15.7915309,5.68078176 L15.7915309,9.88925081 Z M14.1107492,16.6384365 C15.0358306,16.6384365 15.7915309,17.3941368 15.7915309,18.3192182 C15.7915309,19.2442997 15.0358306,20 14.1107492,20 C13.1856678,20 12.4299674,19.2442997 12.4299674,18.3192182 L12.4299674,16.6384365 L14.1107492,16.6384365 Z M14.1107492,15.7915309 C13.1856678,15.7915309 12.4299674,15.0358306 12.4299674,14.1107492 C12.4299674,13.1856678 13.1856678,12.4299674 14.1107492,12.4299674 L18.3192182,12.4299674 C19.2442997,12.4299674 20,13.1856678 20,14.1107492 C20,15.0358306 19.2442997,15.7915309 18.3192182,15.7915309 L14.1107492,15.7915309 Z" />
    </svg>
  );
}
